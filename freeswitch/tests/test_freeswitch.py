from datadog_checks.freeswitch import FreeswitchCheck


def test_check(aggregator, instance):
    check = FreeswitchCheck('freeswitch', {}, {})
    check.check(instance)

    aggregator.assert_all_metrics_covered()
