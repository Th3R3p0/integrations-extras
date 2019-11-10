# Agent Check: FreeSWITCH

## Overview

This check monitors [FreeSWITCH][1] through the Datadog Agent.

## Setup

Follow the instructions below to install and configure this check for an Agent running on a host. For containerized environments, see the [Autodiscovery Integration Templates][2] for guidance on applying these instructions.

### Installation

To install the FreeSWITCH check on your host:

1. Install the [developer toolkit](https://docs.datadoghq.com/developers/integrations/new_check_howto/#developer-toolkit) on any machine.
2. Run `ddev release build freeswitch` to build the package.
3. [Download the Datadog Agent](https://app.datadoghq.com/account/settings#agent).
4. Upload the build artifact to any host with an Agent andrun `datadog-agent integration install -w path/to/freeswitch/dist/<ARTIFACT_NAME>.whl`.

### Configuration

1. Ensure the `mod_xml_rpc` module is enabled on the FreeSWITCH server. You can enable it with the following command: `fs_cli -x 'load mod_xml_rpc'`
1. Edit the `freeswitch.d/conf.yaml` file, in the `conf.d/` folder at the root of your Agent's configuration directory to start collecting your freeswitch performance data. See the [sample freeswitch.d/conf.yaml][3] for all available configuration options.

2. [Restart the Agent][4].

### Validation

[Run the Agent's status subcommand][5] and look for `freeswitch` under the Checks section.

## Data Collected

### Metrics

See [metadata.csv][6] for a list of metrics provided by this check.

### Service Checks

FreeSWITCH does not include any service checks.

### Events

FreeSWITCH does not include any events.

## Troubleshooting

Need help? Contact [Datadog support][7].

[1]: **LINK_TO_INTEGRATION_SITE**
[2]: https://docs.datadoghq.com/agent/autodiscovery/integrations
[3]: https://github.com/DataDog/integrations-core/blob/master/freeswitch/datadog_checks/freeswitch/data/conf.yaml.example
[4]: https://docs.datadoghq.com/agent/guide/agent-commands/?tab=agentv6#start-stop-and-restart-the-agent
[5]: https://docs.datadoghq.com/agent/guide/agent-commands/?tab=agentv6#agent-status-and-information
[6]: https://github.com/DataDog/integrations-core/blob/master/freeswitch/metadata.csv
[7]: https://docs.datadoghq.com/help
