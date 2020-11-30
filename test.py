import sys
import pexpect

result = {'ActionStatus': 'Failed', 'NAS': 'NAT-151', 'Session Up-time': 'Not defined', 'Action': 'show', 'Status': 'Not found', 'Subscriber': '10.16.198.246', 'Last Changed': 'Not defined'}
result2 = {'ActionStatus': 'Success', 'Interim interval expires in': '1188217.7 h', 'Bytes recieved total': '1105947450805', 'Packets transmitted total': '478292211', 'Subscriber': '10.10.205.24', 'Last Changed': 'Not defined', 'Action': 'show', 'Bytes transmitted total': '120749505319', 'NAS': 'NAT-151', 'Idle timeout expires in': '1179058.79 h', 'Maximum data rate downstream total': '97654 Kb/s', 'Packets recieved total': '897643482', 'Service1': 'serviceep', 'Maximum data rate upstream total': '97654 Kb/s', 'Status': 'Authorized', 'Session Up-time': '16h', 'Session timeout expires in': '1188217.7 h'}
result3 =  {'Service1': 'serviceep', 'NAS': 'NAT-154', 'Accounting status': 'Alive', '_SesDuration': 'Not defined', 'Mac': '00:1d:46:5d:18:00', 'Subscriber': '10.27.200.91', 'Last Changed': 'Not defined', 'Idle timeout expires in': '0.5 h', 'Session timeout expires in': '8.88 h', '_SesBytesDown': 'Not defined', 'Packets downstream total': '3111297', 'Action': 'show', '_SesSpeedDown': '78124 Kb/s', 'Session Up-time': 'Not defined', 'Maximum data rate downstream total': '78124 Kb/s', 'Packets upstream total': '1523653', '_SesBytesUp': 'Not defined', 'Status': 'Authorized', '_SesSpeedUp': '78124 Kb/s', 'Contract': 'Undefined', 'Interim interval expires in': '8.77 h', 'Maximum data rate upstream total': '78124 Kb/s', 'Bytes downstream total': '4510222643', 'Bytes upstream total': '137062362', 'Policy': 'policy1', 'ActionStatus': 'Success'}


def addPlaceHolders(res):
    if not isinstance(res, int): 
        if 'Maximum data rate upstream total' in res.keys():
            res['_SesSpeedUp'] = res['Maximum data rate upstream total']
        else:
            res['_SesSpeedUp'] = 'Not defined'

        if 'Maximum data rate downstream total' in res.keys():
            res['_SesSpeedDown'] = res['Maximum data rate downstream total']
        else:
            res['_SesSpeedDown'] = 'Not defined'

        if 'Session Up-time' in res.keys():
            res['_SesDuration'] = res['Session Up-time']
        else:
            res['_SesDuration'] = 'Not defined'

        if 'Bytes transmitted total' in res.keys():
            res['_SesBytesUp'] = res['Bytes transmitted total']
        elif 'Bytes upstream total' in res.keys():
            res['_SesBytesUp'] = res['Bytes upstream total']
        else:
            res['_SesBytesUp'] = 'Not defined'


        if 'Bytes recieved total' in res.keys():
            res['_SesBytesDown'] = res['Bytes recieved total']
        elif 'Bytes downstream total' in res.keys():
            res['_SesBytesDown'] = res['Bytes downstream total'] 
        else:
            res['_SesBytesDown'] = 'Not defined'


addPlaceHolders(result)
addPlaceHolders(result2)
addPlaceHolders(result3)
for key in result3.keys():
    print (key,' ', result3[key])