// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>
    /// Fail-closed JSON object reader. Duplicate keys, unhandled escapes, and broken
    /// structure fail the parse; there is no substring scan for claim names.
    /// </summary>
    internal sealed class JwtJsonObject
    {
        private readonly Dictionary<string, Member> _members;
        private readonly bool _duplicates;

        private JwtJsonObject(Dictionary<string, Member> members, bool duplicates)
        {
            _members = members;
            _duplicates = duplicates;
        }

        public bool HasDuplicates => _duplicates;

        public bool Contains(string name) => _members.ContainsKey(name);

        public bool TryGetString(string name, out string value)
        {
            if (_members.TryGetValue(name, out Member member) && member.Kind == Kind.String)
            {
                value = member.Text!;
                return true;
            }

            value = string.Empty;
            return false;
        }

        public bool TryGetInt64(string name, out long value)
        {
            if (_members.TryGetValue(name, out Member member) && member.Kind == Kind.Integer)
            {
                value = member.Number;
                return true;
            }

            value = 0;
            return false;
        }

        public bool TryGetStringArray(string name, out IReadOnlyList<string> values)
        {
            if (_members.TryGetValue(name, out Member member) && member.Kind == Kind.StringArray)
            {
                values = member.Texts!;
                return true;
            }

            values = Array.Empty<string>();
            return false;
        }

        public static bool TryParse(string json, out JwtJsonObject parsed)
        {
            parsed = new JwtJsonObject(new Dictionary<string, Member>(StringComparer.Ordinal), false);
            if (json is null)
            {
                return false;
            }

            int index = 0;
            if (!TryParseObject(json, ref index, out Dictionary<string, Member> members, out bool duplicates))
            {
                return false;
            }

            index = SkipWs(json, index);
            if (index != json.Length)
            {
                return false;
            }

            parsed = new JwtJsonObject(members, duplicates);
            return !duplicates;
        }

        private static bool TryParseObject(
            string json,
            ref int index,
            out Dictionary<string, Member> members,
            out bool duplicates)
        {
            members = new Dictionary<string, Member>(StringComparer.Ordinal);
            duplicates = false;
            index = SkipWs(json, index);
            if (index >= json.Length || json[index] != '{')
            {
                return false;
            }

            index++;
            index = SkipWs(json, index);
            if (index < json.Length && json[index] == '}')
            {
                index++;
                return true;
            }

            while (index < json.Length)
            {
                if (!TryReadString(json, ref index, out string name))
                {
                    return false;
                }

                index = SkipWs(json, index);
                if (index >= json.Length || json[index] != ':')
                {
                    return false;
                }

                index++;
                if (!TryReadValue(json, ref index, out Member member))
                {
                    return false;
                }

                if (members.ContainsKey(name))
                {
                    duplicates = true;
                    return false;
                }

                members[name] = member;

                index = SkipWs(json, index);
                if (index >= json.Length)
                {
                    return false;
                }

                if (json[index] == '}')
                {
                    index++;
                    return true;
                }

                if (json[index] != ',')
                {
                    return false;
                }

                index++;
                index = SkipWs(json, index);
            }

            return false;
        }

        private static bool TryReadValue(string json, ref int index, out Member member)
        {
            member = default;
            index = SkipWs(json, index);
            if (index >= json.Length)
            {
                return false;
            }

            char c = json[index];
            if (c == '"')
            {
                if (!TryReadString(json, ref index, out string text))
                {
                    return false;
                }

                member = Member.String(text);
                return true;
            }

            if (c == '[')
            {
                if (!TryReadStringArray(json, ref index, out IReadOnlyList<string> texts))
                {
                    return false;
                }

                member = Member.Array(texts);
                return true;
            }

            if (c == '{')
            {
                if (!TryParseObject(json, ref index, out _, out _))
                {
                    return false;
                }

                member = Member.Other();
                return true;
            }

            if (c == '-' || (c >= '0' && c <= '9'))
            {
                return TryReadNumber(json, ref index, out member);
            }

            if (TryReadLiteral(json, ref index, "true") ||
                TryReadLiteral(json, ref index, "false") ||
                TryReadLiteral(json, ref index, "null"))
            {
                member = Member.Other();
                return true;
            }

            return false;
        }

        private static bool TryReadStringArray(string json, ref int index, out IReadOnlyList<string> values)
        {
            values = Array.Empty<string>();
            if (index >= json.Length || json[index] != '[')
            {
                return false;
            }

            index++;
            var list = new List<string>();
            index = SkipWs(json, index);
            if (index < json.Length && json[index] == ']')
            {
                index++;
                values = list;
                return true;
            }

            while (index < json.Length)
            {
                if (!TryReadString(json, ref index, out string item))
                {
                    return false;
                }

                list.Add(item);
                index = SkipWs(json, index);
                if (index >= json.Length)
                {
                    return false;
                }

                if (json[index] == ']')
                {
                    index++;
                    values = list;
                    return true;
                }

                if (json[index] != ',')
                {
                    return false;
                }

                index++;
                index = SkipWs(json, index);
            }

            return false;
        }

        private static bool TryReadNumber(string json, ref int index, out Member member)
        {
            member = default;
            int start = index;
            if (index < json.Length && json[index] == '-')
            {
                index++;
            }

            if (index >= json.Length || json[index] < '0' || json[index] > '9')
            {
                return false;
            }

            if (json[index] == '0')
            {
                index++;
            }
            else
            {
                while (index < json.Length && json[index] >= '0' && json[index] <= '9')
                {
                    index++;
                }
            }

            bool integer = true;
            if (index < json.Length && json[index] == '.')
            {
                integer = false;
                index++;
                if (index >= json.Length || json[index] < '0' || json[index] > '9')
                {
                    return false;
                }

                while (index < json.Length && json[index] >= '0' && json[index] <= '9')
                {
                    index++;
                }
            }

            if (index < json.Length && (json[index] == 'e' || json[index] == 'E'))
            {
                integer = false;
                index++;
                if (index < json.Length && (json[index] == '+' || json[index] == '-'))
                {
                    index++;
                }

                if (index >= json.Length || json[index] < '0' || json[index] > '9')
                {
                    return false;
                }

                while (index < json.Length && json[index] >= '0' && json[index] <= '9')
                {
                    index++;
                }
            }

            string raw = json.Substring(start, index - start);
            if (integer &&
                long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out long number))
            {
                member = Member.Integer(number);
                return true;
            }

            member = Member.Other();
            return true;
        }

        private static bool TryReadString(string json, ref int index, out string value)
        {
            value = string.Empty;
            index = SkipWs(json, index);
            if (index >= json.Length || json[index] != '"')
            {
                return false;
            }

            index++;
            var builder = new StringBuilder();
            while (index < json.Length)
            {
                char c = json[index];
                if (c == '"')
                {
                    index++;
                    value = builder.ToString();
                    return true;
                }

                if (c == '\\')
                {
                    index++;
                    if (index >= json.Length)
                    {
                        return false;
                    }

                    char esc = json[index];
                    index++;
                    switch (esc)
                    {
                        case '"':
                        case '\\':
                        case '/':
                            builder.Append(esc);
                            break;
                        case 'b':
                            builder.Append('\b');
                            break;
                        case 'f':
                            builder.Append('\f');
                            break;
                        case 'n':
                            builder.Append('\n');
                            break;
                        case 'r':
                            builder.Append('\r');
                            break;
                        case 't':
                            builder.Append('\t');
                            break;
                        case 'u':
                            if (index + 4 > json.Length)
                            {
                                return false;
                            }

                            int code = 0;
                            for (int i = 0; i < 4; i++)
                            {
                                int nibble = HexValue(json[index + i]);
                                if (nibble < 0)
                                {
                                    return false;
                                }

                                code = (code << 4) | nibble;
                            }

                            index += 4;
                            builder.Append((char)code);
                            break;
                        default:
                            // Unhandled escape: fail closed rather than swallowing the next character.
                            return false;
                    }

                    continue;
                }

                if (char.IsControl(c))
                {
                    return false;
                }

                builder.Append(c);
                index++;
            }

            return false;
        }

        private static bool TryReadLiteral(string json, ref int index, string literal)
        {
            if (index + literal.Length > json.Length)
            {
                return false;
            }

            for (int i = 0; i < literal.Length; i++)
            {
                if (json[index + i] != literal[i])
                {
                    return false;
                }
            }

            int after = index + literal.Length;
            if (after < json.Length)
            {
                char next = json[after];
                if (char.IsLetterOrDigit(next) || next == '_')
                {
                    return false;
                }
            }

            index = after;
            return true;
        }

        private static int HexValue(char c)
        {
            if (c >= '0' && c <= '9')
            {
                return c - '0';
            }

            if (c >= 'a' && c <= 'f')
            {
                return c - 'a' + 10;
            }

            if (c >= 'A' && c <= 'F')
            {
                return c - 'A' + 10;
            }

            return -1;
        }

        private static int SkipWs(string json, int index)
        {
            while (index < json.Length && char.IsWhiteSpace(json[index]))
            {
                index++;
            }

            return index;
        }

        private enum Kind
        {
            Other,
            String,
            Integer,
            StringArray,
        }

        private readonly struct Member
        {
            private Member(Kind kind, string? text, long number, IReadOnlyList<string>? texts)
            {
                Kind = kind;
                Text = text;
                Number = number;
                Texts = texts;
            }

            public Kind Kind { get; }

            public string? Text { get; }

            public long Number { get; }

            public IReadOnlyList<string>? Texts { get; }

            public static Member String(string value) => new Member(Kind.String, value, 0, null);

            public static Member Integer(long value) => new Member(Kind.Integer, null, value, null);

            public static Member Array(IReadOnlyList<string> values) =>
                new Member(Kind.StringArray, null, 0, values);

            public static Member Other() => new Member(Kind.Other, null, 0, null);
        }
    }
}
