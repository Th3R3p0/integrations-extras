import csv
from socket import gaierror
import re
from xmlrpc.client import ServerProxy
from xmlrpc.client import ProtocolError

from datadog_checks.base import AgentCheck


class FreeswitchCheck(AgentCheck):
    def __init__(self, name, init_config, instances):
        super(FreeswitchCheck, self).__init__(name, init_config, instances)

    def check(self, instance):
        server = ServerProxy("http://%s:%s@%s:%s" % (instance.get('username'),
                                                     instance.get('password'),
                                                     instance.get('host'),
                                                     instance.get('port')))
        self.service_check('FreeSWITCH.rpc.can_connect', self._check_rpc(server))
        registrations = self._get_registrations(server)
        self.gauge('FreeSWITCH.registration.total', len(registrations))
        for registration in registrations:
            self.gauge('FreeSWITCH.registration', 1, tags=['user:{}'.format(registration[0])])
        sessions = self._get_sessions(server)
        self.gauge('FreeSWITCH.sessions', sessions)
        calls = self._get_calls(server)
        for _, value in calls.items():
            self.gauge('FreeSWITCH.calls', value["count"], tags=value["tags"])
        profiles = self._get_sofia_profiles(server)
        for profile in profiles:
            self.gauge('FreeSWITCH.sofia.profile', 1, tags=[
                'profile:{}'.format(profile[0]),
                'status:{}'.format(profile[1])])
        pass

    @staticmethod
    def _check_rpc(server):
        """
        freeswitch@ip-172-31-44-116> show status
        UP 0 years, 1 day, 2 hours, 23 minutes, 48 seconds, 200 milliseconds, 975 microseconds
        FreeSWITCH (Version 1.6.20 -37-987c9b9 64bit) is ready
        43 session(s) since startup
        0 session(s) - peak 5, last 5min 2
        0 session(s) per Sec out of max 30, peak 2, last 5min 1
        1000 session(s) max
        min idle cpu 0.00/99.77
        Current Stack Size/Max 240K/8192K
        """
        try:
            server.freeswitch.api("show", "status")
            return 0
        except gaierror:
            return 2
        except ConnectionRefusedError:
            return 2
        except ProtocolError:
            return 2
        except Exception as e:
            return 3

    @staticmethod
    def _get_registrations(server):
        """
        freeswitch@ip-172-31-44-116> show registrations
        reg_user,realm,token,url,expires,network_ip,network_port,network_proto,hostname,metadata
        1000,172.31.44.116,TOKEN_REDACTED,sofia/internal/sip:1000@1.2.3.4:63103;rinstance=,1573418054,1.2.3.4,63103,udp,ip-172-31-44-116,

        1 total.
        """
        r = server.freeswitch.api("show", "registrations")
        reader = csv.reader(r.split('\n'), delimiter=',')
        # skip the headers
        next(reader, None)
        registrations = []
        for row in reader:
            # the number of columns should be 10. Sometimes it will be different and we want to discard those values
            if len(row) == 10:
                registrations.append(row)
        return registrations

    @staticmethod
    def _get_sessions(server):
        """
        freeswitch@ip-172-31-44-116> show status
        UP 0 years, 1 day, 2 hours, 23 minutes, 48 seconds, 200 milliseconds, 975 microseconds
        FreeSWITCH (Version 1.6.20 -37-987c9b9 64bit) is ready
        43 session(s) since startup
        0 session(s) - peak 5, last 5min 2
        0 session(s) per Sec out of max 30, peak 2, last 5min 1
        1000 session(s) max
        min idle cpu 0.00/99.77
        Current Stack Size/Max 240K/8192K
        """
        status = server.freeswitch.api("show", "status")
        num_channels = r'(?P<sessions>\d+) \w.* - peak'
        regexp = re.compile(num_channels)
        matches = regexp.search(status)
        sessions = int(matches.group("sessions"))
        return sessions

    @staticmethod
    def _get_calls(server):
        """
        freeswitch@ip-172-31-44-116> show calls
        uuid,direction,created,created_epoch,name,state,cid_name,cid_num,ip_addr,dest,presence_id,presence_data,accountcode,callstate,callee_name,callee_num,callee_direction,call_uuid,hostname,sent_callee_name,sent_callee_num,b_uuid,b_direction,b_created,b_created_epoch,b_name,b_state,b_cid_name,b_cid_num,b_ip_addr,b_dest,b_presence_id,b_presence_data,b_accountcode,b_callstate,b_callee_name,b_callee_num,b_callee_direction,b_sent_callee_name,b_sent_callee_num,call_created_epoch
        0e0ec720-01e9-4e59-abe5-b4c56fdb7e14,inbound,2019-11-10 19:57:29,1573415849,sofia/internal/1000@freeswitch,CS_EXECUTE,+18009999999,1000,1.2.3.4,1000,1000@freeswitch,,1000,EARLY,,,,,ip-172-31-44-116,,,,,,,,,,,,,,,,,,,,,,
        ca017a69-c19c-4796-b644-76b87ce55ee5,outbound,2019-11-10 19:57:39,1573415859,sofia/internal/1000@1.2.3.4:63103,CS_CONSUME_MEDIA,Extension 1000,1000,1.2.3.4,1000,1000@172.31.44.116,,,RINGING,Outbound Call,1000,,0e0ec720-01e9-4e59-abe5-b4c56fdb7e14,ip-172-31-44-116,,,,,,,,,,,,,,,,,,,,,,

        2 total.
        """
        # todo: add all statuses.
        calls = {
            "EARLY-inbound": {"count": 0, "tags": ["direction:inbound", "state:EARLY"]},
            "EARLY-outbound": {"count": 0, "tags": ["direction:outbound", "state:EARLY"]},
            "ACTIVE-inbound": {"count": 0, "tags": ["direction:inbound", "state:ACTIVE"]},
            "ACTIVE-outbound": {"count": 0, "tags": ["direction:outbound", "state:ACTIVE"]},
            "RINGING-inbound": {"count": 0, "tags": ["direction:inbound", "state:RINGING"]},
            "RINGING-outbound": {"count": 0, "tags": ["direction:outbound", "state:RINGING"]}
        }
        r = server.freeswitch.api("show", "calls")
        reader = csv.reader(r.split('\n'), delimiter=',')
        # skip the headers
        next(reader, None)
        for row in reader:
            if len(row) == 41:
                direction = row[1]
                state = row[13]
                try:
                    calls["{state}-{direction}".format(state=state, direction=direction)]["count"] += 1
                except:
                    pass
        return calls

    @staticmethod
    def _get_sofia_profiles(server):
        """
        freeswitch@ip-172-31-44-116> sofia status
                             Name	   Type	                                      Data	State
        =================================================================================================
                    external-ipv6	profile	                  sip:mod_sofia@[::1]:5080	RUNNING (0)
                         external	profile	          sip:mod_sofia@172.31.44.116:5080	RUNNING (0)
            external::example.com	gateway	                   sip:joeuser@example.com	NOREG
                    172.31.44.116	  alias	                                  internal	ALIASED
                    internal-ipv6	profile	                  sip:mod_sofia@[::1]:5060	RUNNING (0)
                         internal	profile	          sip:mod_sofia@172.31.44.116:5060	RUNNING (0)
        =================================================================================================
        4 profiles 1 alias
        """
        r = server.freeswitch.api("sofia", "status")
        regexp = re.compile(r'\n\s*([^=]\S*)\sprofile[^s]\s*\S*\s(\S*)')
        return regexp.findall(r)
