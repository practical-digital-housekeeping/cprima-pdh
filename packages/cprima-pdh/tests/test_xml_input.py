"""Cases written as KDBX-shaped XML, so a real entry can be pasted in as a test case."""
from pdh_testkit.stubs import entries_from_xml, StubKP

from cprima_pdh.schema import parse_schemas, validate

SCHEMAS = parse_schemas("""
[facet.login]
required = ["Title", "UserName", "Password", "URL"]
https_only = true

[schema.website]
facets = ["login"]
""")

# A whole (tiny) database: root group > Money > Banks, one valid and one broken entry,
# plus an entry in the Recycle Bin-like top group that is simply unclassified.
DATABASE = """
<KeePassFile><Root>
  <Group><Name>Root</Name>
    <Group><Name>Money</Name>
      <Group><Name>Banks</Name>
        <Entry>
          <UUID>00000000-0000-0000-0000-000000000001</UUID>
          <String><Key>Title</Key><Value>Good Bank</Value></String>
          <String><Key>UserName</Key><Value>me</Value></String>
          <String><Key>Password</Key><Value Protected="True">pw</Value></String>
          <String><Key>URL</Key><Value>https://bank.example</Value></String>
          <String><Key>_schema</Key><Value>website</Value></String>
        </Entry>
        <Entry>
          <UUID>00000000-0000-0000-0000-000000000002</UUID>
          <String><Key>Title</Key><Value>Bad Bank</Value></String>
          <String><Key>UserName</Key><Value/></String>
          <String><Key>Password</Key><Value Protected="True">pw</Value></String>
          <String><Key>URL</Key><Value>http://bank.example</Value></String>
          <String><Key>_schema</Key><Value>website</Value></String>
        </Entry>
      </Group>
    </Group>
    <Entry>
      <UUID>00000000-0000-0000-0000-000000000003</UUID>
      <String><Key>Title</Key><Value>Loose</Value></String>
    </Entry>
  </Group>
</Root></KeePassFile>
"""


def test_database_xml_drives_the_same_rules():
    entries = entries_from_xml(DATABASE)
    assert [e.title for e in entries] == ["Good Bank", "Bad Bank", "Loose"]
    assert entries[0].group.path == ["Money", "Banks"]  # the root group is not part of the path
    report = validate(StubKP(entries), SCHEMAS)
    assert {(f.entry, f.rule) for f in report.findings} == {
        ("Money/Banks/Bad Bank", "required:UserName"),
        ("Money/Banks/Bad Bank", "url:https"),
    }
    assert report.unclassified_entries == 1


def test_single_entry_snippet():
    xml = """
    <Entry>
      <String><Key>Title</Key><Value>Snippet</Value></String>
      <String><Key>UserName</Key><Value>me</Value></String>
      <String><Key>Password</Key><Value Protected="True">pw</Value></String>
      <String><Key>URL</Key><Value>https://x.example</Value></String>
      <String><Key>_schema</Key><Value>website</Value></String>
    </Entry>"""
    (entry,) = entries_from_xml(xml, default_group="Area")
    assert not validate(StubKP([entry]), SCHEMAS).findings
