import requests
import json
import time

defense = {'icmp': True,
           'syn': True,
           'dns_amplifier': True,
           'udp': True}
black_list = []
block_time = 360
fw_priority = '32767'
sFlow_RT = 'http://10.10.10.2:8008'
floodlight = 'http://10.10.10.2:8080'

groups = {'external': ['0.0.0.0/0'], 'internal': ['10.0.0.2/32'], 'dns_internal': ['10.0.0.1/32', '10.0.0.2/32']}

value = 'bytes'  # set to 'bytes' and multiply 8 to get bits/second


# define ICMP flood attack attributes #
icmp_flood_keys = 'inputifindex,ethernetprotocol,macsource,macdestination,ipprotocol,ipsource,ipdestination'
icmp_flood_metric_name = 'icmp_flood'
icmp_flood_threshold_value = 100
icmp_flood_filter = 'group:ipsource:lf=external&group:ipdestination:lf=internal&outputifindex!=discard&ipprotocol=1'
icmp_flood_flows = {'keys': icmp_flood_keys, 'value': value, 'filter': icmp_flood_filter}
icmp_flood_threshold = {'metric': icmp_flood_metric_name, 'value': icmp_flood_threshold_value}

# define SYN flood attack attributes #
syn_flood_keys = 'inputifindex,ethernetprotocol,macsource,macdestination,ipprotocol,ipsource,ipdestination'
syn_flood_metric_name = 'syn_flood'
syn_flood_threshold_value = 100
syn_flood_filter = 'group:ipsource:lf=external&group:ipdestination:lf=internal&outputifindex!=discard&tcpflags~.......1.'
syn_flood_flows = {'keys': syn_flood_keys, 'value': value, 'filter': syn_flood_filter}
syn_flood_threshold = {'metric': syn_flood_metric_name, 'value': syn_flood_threshold_value}

# define UDP flood attack attributes # *****REVERSED*****
udp_flood_keys = 'inputifindex,ethernetprotocol,macsource,macdestination,ipprotocol,ipsource,ipdestination'
udp_flood_metric_name = 'dns_amplifier'
udp_flood_threshold_value = 100
udp_flood_filter = 'group:ipsource:lf=internal&group:ipdestination:lf=external&outputifindex!=discard&ipprotocol=1&icmptype=3'
udp_flood_flows = {'keys': udp_flood_keys, 'value': value, 'filter': udp_flood_filter}
udp_flood_threshold = {'metric': udp_flood_metric_name, 'value': udp_flood_threshold_value}


# define DNS ANY(15) amplifier attack attributes #
dns_amplifier_keys = 'inputifindex,ethernetprotocol,macsource,macdestination,ipprotocol,ipsource,ipdestination'
dns_amplifier_metric_name = 'dns_amplifier'
dns_amplifier_threshold_value = 100
dns_amplifier_filter = 'group:ipsource:lf=external&group:ipdestination:lf=dns_internal&outputifindex!=discard&dnsqr=false&dnsqtype=255'
dns_amplifier_flows = {'keys': dns_amplifier_keys, 'value': value, 'filter': dns_amplifier_filter}
dns_amplifier_threshold = {'metric': dns_amplifier_metric_name, 'value': dns_amplifier_threshold_value}


#r = requests.put(sFlow_RT + '/group/json', data=json.dumps(groups))
r = requests.put(sFlow_RT + '/group/lf/json', data=json.dumps(groups))

if defense['icmp']:
    # define flows and threshold of ICMP flood
    r = requests.put(sFlow_RT + '/flow/' + icmp_flood_metric_name + '/json', data=json.dumps(icmp_flood_flows))
    r = requests.put(sFlow_RT + '/threshold/' + icmp_flood_metric_name + '/json', data=json.dumps(icmp_flood_threshold))

if defense['syn']:
    # define flows and threshold of SYN flood
    r = requests.put(sFlow_RT + '/flow/' + syn_flood_metric_name + '/json', data=json.dumps(syn_flood_flows))
    r = requests.put(sFlow_RT + '/threshold/' + syn_flood_metric_name + '/json', data=json.dumps(syn_flood_threshold))

if defense['dns_amplifier']:
    r = requests.put(sFlow_RT + '/flow/' + dns_amplifier_metric_name + '/json', data=json.dumps(dns_amplifier_flows))
    r = requests.put(sFlow_RT + '/threshold/' + dns_amplifier_metric_name + '/json', data=json.dumps(dns_amplifier_threshold))

if defense['udp']:
    r = requests.put(sFlow_RT + '/flow/' + udp_flood_metric_name + '/json', data=json.dumps(udp_flood_flows))
    r = requests.put(sFlow_RT + '/threshold/' + udp_flood_metric_name + '/json', data=json.dumps(udp_flood_threshold))


event_url = sFlow_RT + '/events/json?maxEvents=10&timeout=60'
eventID = -1

while True:
    if black_list.__len__() > 0 and black_list[0][0] < time.time():
        r = requests.delete(floodlight + '/wm/staticflowentrypusher/json', data=black_list.pop(0)[1])
        print r.json()['status']

    r = requests.get(event_url + '&eventID=' + str(eventID))
    events = r.json()

    if events.__len__() > 0:
        eventID = events[0]["eventID"]
    events.reverse()

    for e in events:
        if e['metric'] == syn_flood_metric_name:
            r = requests.get(sFlow_RT + '/metric/' + e['agent'] + '/' + e['dataSource'] + '.' + e['metric'] + '/json')
            metrics = r.json()
            if metrics and metrics.__len__() > 0:
                metric = metrics[0]
                if metric.__contains__("metricValue") \
                        and metric['metricValue'] > syn_flood_threshold_value\
                        and metric['topKeys']\
                        and metric['topKeys'].__len__() > 0:

                    for topKey in metric['topKeys']:
                        if topKey['value'] > syn_flood_threshold_value:
                            key = topKey['key']
                            print key,
                            parts = key.split(',')

                            message = {'switch': 1,
                                       'name': 'SYN_block_'+parts[5],
                                       'ether-type': parts[1],
                                       'protocol': parts[4],
                                       'src-ip': parts[5],
                                       'dst-ip': parts[6],
                                       'priority': fw_priority,
                                       'active': 'true'}
                            push_data = json.dumps(message)
                            r = requests.post(floodlight + '/wm/staticflowentrypusher/json', data=push_data)
                            black_list.append([time.time()+block_time, push_data])
                            result = r.json()
                            print ""
                            print result['status']
                    print ""

        elif e['metric'] == icmp_flood_metric_name:
            r = requests.get(sFlow_RT + '/metric/' + e['agent'] + '/' + e['dataSource'] + '.' + e['metric'] + '/json')
            metrics = r.json()
            if metrics and metrics.__len__() > 0:
                metric = metrics[0]
                if metric.__contains__("metricValue") \
                        and metric['metricValue'] > icmp_flood_threshold_value\
                        and metric['topKeys']\
                        and metric['topKeys'].__len__() > 0:

                    for topKey in metric['topKeys']:
                        if topKey['value'] > icmp_flood_threshold_value:
                            key = topKey['key']
                            print key,
                            parts = key.split(',')

                            message = {'switch': 1,
                                       'name': 'ICMP_block_'+parts[5],
                                       'ether-type': parts[1],
                                       'protocol': parts[4],
                                       'src-ip': parts[5],
                                       'dst-ip': parts[6],
                                       'priority': fw_priority,
                                       'active': 'true'}
                            push_data = json.dumps(message)
                            r = requests.post(floodlight + '/wm/staticflowentrypusher/json', data=push_data)
                            black_list.append([time.time()+block_time, push_data])
                            result = r.json()
                            print ""
                            print result['status']
                    print ""

        elif e['metric'] == dns_amplifier_metric_name:
            r = requests.get(sFlow_RT + '/metric/' + e['agent'] + '/' + e['dataSource'] + '.' + e['metric'] + '/json')
            metrics = r.json()
            if metrics and metrics.__len__() > 0:
                metric = metrics[0]
                if metric.__contains__("metricValue") \
                        and metric['metricValue'] > dns_amplifier_threshold_value\
                        and metric['topKeys']\
                        and metric['topKeys'].__len__() > 0:

                    for topKey in metric['topKeys']:
                        if topKey['value'] > dns_amplifier_threshold_value:
                            key = topKey['key']
                            print key,
                            parts = key.split(',')

                            message = {'switch': 1,
                                       'name': 'DNS_block_'+parts[5],
                                       'ether-type': parts[1],
                                       'protocol': parts[4],
                                       'src-ip': parts[5],
                                       'dst-ip': parts[6],
                                       'priority': fw_priority,
                                       'active': 'true'}
                            push_data = json.dumps(message)
                            r = requests.post(floodlight + '/wm/staticflowentrypusher/json', data=push_data)
                            black_list.append([time.time()+block_time, push_data])
                            result = r.json()
                            print ""
                            print result['status']
                    print ""
        elif e['metric'] == udp_flood_metric_name:
            r = requests.get(sFlow_RT + '/metric/' + e['agent'] + '/' + e['dataSource'] + '.' + e['metric'] + '/json')
            metrics = r.json()
            if metrics and metrics.__len__() > 0:
                metric = metrics[0]
                if metric.__contains__("metricValue") \
                        and metric['metricValue'] > udp_flood_threshold_value\
                        and metric['topKeys']\
                        and metric['topKeys'].__len__() > 0:

                    for topKey in metric['topKeys']:
                        if topKey['value'] > udp_flood_threshold_value:
                            key = topKey['key']
                            print key,
                            parts = key.split(',')

                            message = {'switch': 1,
                                       'name': 'UDP_block_'+parts[6],
                                       'ether-type': '2048',
                                       'src-ip': parts[6], #reversed src&dst IP
                                       'dst-ip': parts[5],
                                       'priority': fw_priority,
                                       'active': 'true'}
                            push_data = json.dumps(message)
                            r = requests.post(floodlight + '/wm/staticflowentrypusher/json', data=push_data)
                            black_list.append([time.time()+block_time, push_data])
                            result = r.json()
                            print ""
                            print result['status']
                    print ""