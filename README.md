# WeblogicLogs-Wazuh
A Decoder for Wazuh to collect valuable logs from Weblogic

```
<!-- Custom decoder for WebLogic logs -->
<decoder name="weblogic">
  <parent>syslog</parent>
  <order>100</order>
  <decoder client_id="weblogic">
    <regex>
      ^\w{3}\s+\d+\s+\d+:\d+:\d+\s+\w+\s+(\w+)\[(\d+)\]:\s+(.*)
    </regex>
    <order>10</order>
    <parent>weblogic</parent>
    <decoder client_id="weblogic">
      <match>
        <regex>
          \[(\d+)\]:\s+ERROR\s+.*:\s+(.*)
        </regex>
        <field name="pid" search="regex" expression="(\d+)" />
        <field name="message" search="regex" expression="\s+ERROR\s+.*:\s+(.*)" />
        <field name="srcip" />
        <field name="program_name" value="weblogic" />
      </match>
    </decoder>
  </decoder>
```

## After loading the Decoder, add the rules

```
<!-- Rule to detect critical errors in WebLogic logs -->
<rule id="100100" level="10">
  <if_sid>100</if_sid>
  <field name="program_name">weblogic</field>
  <field name="message">.*CRITICAL.*</field>
  <description>Critical error detected in WebLogic logs</description>
</rule>

<!-- Rule to detect high-severity errors in WebLogic logs -->
<rule id="100101" level="7">
  <if_sid>100</if_sid>
  <field name="program_name">weblogic</field>
  <field name="message">.*ERROR.*</field>
  <description>High-severity error detected in WebLogic logs</description>
</rule>
```
