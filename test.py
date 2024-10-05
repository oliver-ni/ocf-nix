#!/usr/bin/env python3

from __future__ import annotations

import argparse
import configparser
from dataclasses import dataclass
import enum
import sys
import traceback
from textwrap import dedent, indent
from typing import Dict, List, Optional, Union, cast


def ensure_indent(text: str, numspaces: int = 4) -> str:
    return indent(dedent(text), " " * numspaces)


class PolkitConfConverterException(Exception):
    def __init__(self, msg: str):
        super().__init__()
        self.msg = msg


class PolkitIdType(enum.Enum):
    USER = enum.auto()
    GROUP = enum.auto()
    NETGROUP = enum.auto()

    @classmethod
    def parse_identity_type(cls, input: str) -> PolkitIdType:
        result_map = {
            "unix-user": cls.USER,
            "unix-group": cls.GROUP,
            "unix-netgroup": cls.NETGROUP,
        }

        try:
            return result_map[input]
        except KeyError as e:
            raise PolkitConfConverterException("Unknown polkit identity type") from e


class PolkitResult(enum.Enum):
    YES = enum.auto()
    NO = enum.auto()
    AUTH_SELF = enum.auto()
    AUTH_SELF_KEEP = enum.auto()
    AUTH_ADMIN = enum.auto()
    AUTH_ADMIN_KEEP = enum.auto()

    @classmethod
    def parse_polkit_result(
        cls, polkit_result: Optional[str]
    ) -> Optional[PolkitResult]:
        if polkit_result is None:
            return None

        result_map = {
            "yes": cls.YES,
            "no": cls.NO,
            "auth_self": cls.AUTH_SELF,
            "auth_self_keep": cls.AUTH_SELF_KEEP,
            "auth_admin": cls.AUTH_ADMIN,
            "auth_admin_keep": cls.AUTH_ADMIN_KEEP,
        }

        try:
            return result_map[polkit_result]
        except KeyError as e:
            raise PolkitConfConverterException("Unknown polkit result value") from e

    @classmethod
    def polkit_result_str(cls, element: PolkitResult) -> Optional[str]:
        result_map = {
            cls.YES: "polkit.Result.YES",
            cls.NO: "polkit.Result.NO",
            cls.AUTH_SELF: "polkit.Result.AUTH_SELF",
            cls.AUTH_SELF_KEEP: "polkit.Result.AUTH_SELF_KEEP",
            cls.AUTH_ADMIN: "polkit.Result.AUTH_ADMIN",
            cls.AUTH_ADMIN_KEEP: "polkit.Result.AUTH_ADMIN_KEEP",
        }

        try:
            return result_map[element]
        except KeyError:
            return None


@dataclass
class PolkitIdentity:
    identity_type: PolkitIdType
    identity: str

    def __str__(self) -> str:
        if self.identity_type is PolkitIdType.USER:
            return f"unix-user:{self.identity}"
        elif self.identity_type is PolkitIdType.GROUP:
            return f"unix-group:{self.identity}"
        elif self.identity_type is PolkitIdType.NETGROUP:
            return f"unix-netgroup:{self.identity}"
        else:
            raise PolkitConfConverterException("Illegal PolkitIdType")

    @classmethod
    def parse_identity_str(cls, input: str) -> PolkitIdentity:
        id_type, id_name = input.split(":", maxsplit=1)
        return cls(
            identity_type=PolkitIdType.parse_identity_type(id_type), identity=id_name
        )


@dataclass
class PolkitAdminConf:
    admin_identity: List[PolkitIdentity]

    def to_javascript(self) -> str:
        result_list = [str(i) for i in self.admin_identity]
        return dedent(
            f"""\
            polkit.addAdminRule(function(action, subject) {{
                return {result_list};
            }});
            """
        )


@dataclass
class PolkitPKLA:
    identity: List[PolkitIdentity]
    action: List[str]
    result_active: Optional[PolkitResult]
    result_inactive: Optional[PolkitResult]
    result_any: Optional[PolkitResult]
    return_value: Optional[Dict[str, str]]

    def format_action_expression(self, action: str) -> str:
        if "*" in action:
            if action.endswith("*"):
                return f'action.startsWith("{action[:-1]}")'

            raise PolkitConfConverterException(
                "Automatic conversion of globbing only at end of action string supported."
            )

        return f'action.id == "{action}"'

    def format_id_expression(self, id: PolkitIdentity) -> str:
        if id.identity_type is PolkitIdType.USER:
            return f'subject.user == "{id.identity}"'
        elif id.identity_type is PolkitIdType.GROUP:
            return f'subject.isInGroup("{id.identity}")'
        elif id.identity_type is PolkitIdType.NETGROUP:
            return f'subject.isInNetGroup("{id.identity}")'
        else:
            raise PolkitConfConverterException("Illegal PolkitIdType")

    def or_conditionals(self, conds: List[str], numspaces=8) -> str:
        if len(conds) > 1:
            numspaces += 1

        c = ensure_indent(" ||\n".join(conds), numspaces)

        if len(conds) > 1:
            c = " " * (numspaces - 1) + "(" + c.lstrip() + ")"
        return c

    def to_javascript(self) -> str:
        if self.return_value:
            raise PolkitConfConverterException(
                "Automatic conversion of PKLA return values is not supported."
            )

        action_conds = self.or_conditionals([self.format_action_expression(a) for a in self.action])
        identity_conds = self.or_conditionals([self.format_id_expression(i) for i in self.identity])

        if action_conds and identity_conds:
            merged_conds = dedent(
                """\
                {action_conds} &&
                {identity_conds}
                """
            ).format(
                action_conds=action_conds.lstrip(),
                identity_conds=identity_conds.rstrip()
            ).rstrip()
        elif action_conds:
            merged_conds = action_conds
        elif identity_conds:
            merged_conds = identity_conds
        else:
            merged_conds = "true"

        if self.result_any and (
            (not self.result_active and not self.result_inactive)
            or (not self.result_active and self.result_inactive is self.result_any)
            or (not self.result_inactive and self.result_active is self.result_any)
            or (
                self.result_active is self.result_any
                and self.result_inactive is self.result_any
            )
        ):
            results = ensure_indent(
                f"return {PolkitResult.polkit_result_str(self.result_any)};",
                numspaces=8,
            )
        else:
            if self.result_active:
                result_active = ensure_indent(
                    f"""\
                    if (subject.active && subject.local) {{
                        return {PolkitResult.polkit_result_str(self.result_active)};
                    }}
                    """,
                    numspaces=8,
                )
            else:
                result_active = ""

            if self.result_inactive:
                result_inactive = ensure_indent(
                    f"""\
                    if (subject.inactive && subject.local) {{
                        return {PolkitResult.polkit_result_str(self.result_inactive)};
                    }}
                    """,
                    numspaces=8,
                )
            else:
                result_inactive = ""

            if self.result_any:
                result_any = ensure_indent(
                    f"return {PolkitResult.polkit_result_str(self.result_any)};",
                    numspaces=8,
                )
            else:
                result_any = ""

            results = "".join((result_active, result_inactive, result_any))

        body = dedent(
            """\
            polkit.addRule(function(action, subject) {{
                if ({merged_conds})
                {{
            {results}
                }}
            }});
            """
        )

        return body.format(merged_conds=merged_conds, results=results)


def _parse_ini_section(
    section: configparser.SectionProxy,
) -> Union[PolkitAdminConf, PolkitPKLA]:
    if section.get("AdminIdentities"):
        admin_ids = [
            PolkitIdentity.parse_identity_str(i)
            for i in section["AdminIdentities"].split(";") if i
        ]
        return PolkitAdminConf(admin_identity=admin_ids)

    identity = section.get("Identity")
    action = section.get("Action")
    result_active = PolkitResult.parse_polkit_result(section.get("ResultActive"))
    result_inactive = PolkitResult.parse_polkit_result(section.get("ResultInactive"))
    result_any = PolkitResult.parse_polkit_result(section.get("ResultAny"))
    return_value = section.get("ReturnValue")

    if (
        not identity
        or not action
        or not (result_active or result_inactive or result_any)
    ):
        raise PolkitConfConverterException("Invalid input configuration")

    identity = [PolkitIdentity.parse_identity_str(i) for i in identity.split(";") if i]
    action = [i for i in action.split(";") if i]

    if return_value:
        return_value = dict([r.split("=", maxsplit=1) for r in return_value.split(";")])  # type: ignore

    return PolkitPKLA(
        identity=identity,
        action=action,
        result_active=result_active,
        result_inactive=result_inactive,
        result_any=result_any,
        return_value=cast(Optional[Dict[str, str]], return_value),
    )


# Main CLI function
def main() -> bool:
    parser = argparse.ArgumentParser(
        description="Convert old polkit config to new one."
    )
    parser.add_argument(
        "input",
        nargs="?",
        metavar="INPUT",
        type=argparse.FileType("r"),
        default=sys.stdin,
        help='Input file, can be "-" for stdin.',
    )
    parser.add_argument(
        "output",
        nargs="?",
        metavar="OUTPUT",
        type=argparse.FileType("w"),
        default=sys.stdout,
        help='Output file, can be "-" for stdout.',
    )
    parser.add_argument(
        "-d", "--debug", action="store_true", help="Enable debugging output."
    )

    args = parser.parse_args()

    input_config = configparser.ConfigParser()
    input_config.read_file(args.input)

    try:
        for section in input_config.sections():
            conf_obj = _parse_ini_section(input_config[section])
            args.output.write(conf_obj.to_javascript())
    except PolkitConfConverterException as e:
        if args.debug:
            traceback.print_exc()
        else:
            print(e.msg, file=sys.stderr)
        return False

    return True


if __name__ == "__main__":
    sys.exit(main())

