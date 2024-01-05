# AzureWAFRuleSentinel
This repository provides Detect Blocked / Non-Blocked Events of Azure WAF on Microsoft Sentinel.

# Screenshot
<img width="1071" alt="image" src="https://github.com/hisashin0728/AzureWAFRuleSentinel/assets/55295601/d0be7735-ffcd-4eb1-bc97-449d0b41e3ad">

# Rule

- Detected Non-Blocked events from Azure WAF on AGW
 - Severity : Middle
 - Description : ブロックモードではない Azure WAF のイベントを検知しました。
 - KQL

```
let queryperiod = 1h;
AzureDiagnostics
| where TimeGenerated > ago(queryperiod)
| where Category == 'ApplicationGatewayFirewallLog'
| where action_s in ("Detected","Allowed","Matched")
| project TimeGenerated,ResourceId,instanceId_s,hostname_s, policyScopeName_s, ruleSetType_s, ruleId_s,action_s, clientIp_s, requestUri_s, Message,details_message_s
```

- Detected Blocked events from Azure WAF on AGW
 - Severity : Low
 - Description : ブロックモードで防御された Azure WAF のイベントを検知しました。
 - KQL

```
let queryperiod = 1h;
AzureDiagnostics
| where TimeGenerated > ago(queryperiod)
| where Category == 'ApplicationGatewayFirewallLog'
| where action_s == 'Blocked'
| project TimeGenerated,ResourceId,instanceId_s,hostname_s, policyScopeName_s, ruleSetType_s, ruleId_s,action_s, clientIp_s, requestUri_s, Message,details_message_s
```
