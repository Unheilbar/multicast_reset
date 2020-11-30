#!env/bin/python3

import pexpect
import sys
import re
import logging
import logging.config
from ipaddress import ip_network

def sec2hours(time):
    (sec, _) = time.split(' ')
    hours = str(round(float(sec) / 3600, 2)) + " h"
    return hours

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
        elif 'Bytes downstream total' in res.keys:
            res['_SesBytesDown'] = res['Bytes downstream total'] 
        else:
            res['_SesBytesDown'] = 'Not defined'

def asrSubSessionActions(nas_ip, sub_ip, action, logger, login, password):
    p = pexpect.spawn('telnet %s' % nas_ip, timeout=5, encoding='utf-8')
    p.setwinsize(80, 40)
    result = p.expect(['Username:', pexpect.EOF, pexpect.TIMEOUT])
    if result == 1 or result == 2:
        logger.error("Failed  to connect " + nas_ip)
        p.close()
        return 404
    p.sendline(login)
    p.expect(['Password:'])
    p.sendline(password)
    result = p.expect(['>', pexpect.EOF, pexpect.TIMEOUT])
    if result == 1 or result == 2:
        logger.error("Failed  to login " + nas_ip)
        p.close()
        return 403
    if action == 'show':
        p.sendline('show subscriber session identifier source-ip-address ' + sub_ip + ' 255.255.255.255')
        result = p.expect(['>', pexpect.EOF, pexpect.TIMEOUT])
        if result == 1 or result == 2:
            logger.error("Failed  to get subscriber session " + sub_ip)
            p.close()
            return 402
        sub_session_info = p.before.splitlines()[1:-1]
        sub_session_params = {}
        sub_session_parser_flag = 0
        head = [[]]
        body = [[[]]]

        print(sub_session_info)

        for sub_session_str in sub_session_info:
            if not sub_session_str:
                continue
            if sub_session_parser_flag == 0:
                if 'Type:' in sub_session_str:
                    sub_session_str_split = sub_session_str.split(',')
                    for sub_session_str_hash in sub_session_str_split:
                        [key, value] = sub_session_str_hash.split(':')
                        sub_session_params[key.strip()] = value.strip()
                elif 'IPv4 Address:' in sub_session_str or 'Switch-ID' in sub_session_str:
                    [key, value] = sub_session_str.split(':')
                    sub_session_params[key.strip()] = value.strip()
                elif 'Session Up-time:' in sub_session_str:
                    sub_session_str_split = sub_session_str.split(',')
                    for sub_session_str_hash in sub_session_str_split:
                        [key, value] = sub_session_str_hash.split(':', 1)
                        sub_session_params[key.strip()] = value.strip()
                elif 'Policy information:' in sub_session_str:
                    sub_session_parser_flag = 1
            elif sub_session_parser_flag == 1:
                if 'Accounting:' in sub_session_str:
                    sub_session_parser_flag = 2
                    sub_session_table_template_cells = [8, 3, 9, 21, 7]
                    sub_session_table_template_spaces = [3, 2, 1, 1]
                    head_flag = 1
                    body_flag = 0
                    body_counter = 0
                    step = 0
            elif sub_session_parser_flag == 2:
                if 'Policing:' in sub_session_str:
                    sub_session_parser_flag = 3
                    sub_session_table_template_cells = [8, 3, 9, 12, 12, 7]
                    sub_session_table_template_spaces = [3, 2, 3, 2, 1]
                    head_flag = 1
                    body_flag = 0
                    body_counter = 0
                    step = 1
                else:
                    i = 0
                    if head_flag == 1:
                        for cell in sub_session_table_template_cells:
                            head[step].append(sub_session_str[:cell].strip(' '))
                            if i < (len(sub_session_table_template_cells) - 1):
                                sub_session_str = sub_session_str[cell:]
                                try:
                                    sub_session_str = sub_session_str[sub_session_table_template_spaces[i]:]
                                except:
                                    pass
                            i = i + 1
                        head_flag = 0
                        body_flag = 1
                    elif body_flag == 1:
                        if body_counter == 1:
                            body[step].append([])
                        for cell in sub_session_table_template_cells:
                            body[step][body_counter].append(sub_session_str[:cell].strip(' '))
                            if i < (len(sub_session_table_template_cells) - 1):
                                sub_session_str = sub_session_str[cell:]
                                try:
                                    sub_session_str = sub_session_str[sub_session_table_template_spaces[i]:]
                                except:
                                    pass
                            i = i + 1
                        body_counter = body_counter + 1
            elif sub_session_parser_flag == 3:
                if 'Configuration Sources:' in sub_session_str:
                    break
                else:
                    i = 0
                    if head_flag == 1:
                        head.append([])
                        for cell in sub_session_table_template_cells:
                            head[step].append(sub_session_str[:cell].strip(' '))
                            if i < (len(sub_session_table_template_cells) - 1):
                                sub_session_str = sub_session_str[cell:]
                                try:
                                    sub_session_str = sub_session_str[sub_session_table_template_spaces[i]:]
                                except:
                                    pass
                            i = i + 1
                        head_flag = 0
                        body_flag = 1
                    elif body_flag == 1:
                        if body_counter == 0:
                            body.append([])
                        body[step].append([])
                        for cell in sub_session_table_template_cells:
                            body[step][body_counter].append(sub_session_str[:cell].strip(' '))
                            if i < (len(sub_session_table_template_cells) - 1):
                                sub_session_str = sub_session_str[cell:]
                                try:
                                    sub_session_str = sub_session_str[sub_session_table_template_spaces[i]:]
                                except:
                                    pass
                            i = i + 1
                        body_counter = body_counter + 1
        if sub_session_params:
            parts = ['Accounting', 'Policing']
            i = 0

            for keys in head:
                tmp_dict1 = {}
                tmp_dict2 = {}
                sub_session_params[parts[i]] = []
                j = 0
                k = 0
                for key in keys:
                    tmp_dict1[key] = body[i][j][k]
                    tmp_dict2[key] = body[i][j + 1][k]
                    k = k + 1
                sub_session_params[parts[i]].append(tmp_dict1)
                sub_session_params[parts[i]].append(tmp_dict2)
                i = i + 1
            sub_session_params['ActionStatus'] = 'Success'
            if 'Type' in sub_session_params:
                sub_session_params.pop('Type')
            if 'UID' in sub_session_params:
                sub_session_params.pop('UID')
            if sub_session_params['State'] == 'authen':
                sub_session_params.pop('State')
                sub_session_params['Status'] = 'Authorized'
            sub_session_params.pop('Identity')
            sub_session_params['Subscriber'] = sub_session_params.pop('IPv4 Address')
            sub_session_params.pop('Switch-ID')
            for sub_session_param in sub_session_params['Accounting']:
                if sub_session_param['Dir'] == 'In':
                    sub_session_params['Bytes recieved total'] = sub_session_param['Bytes']
                    sub_session_params['Packets recieved total'] = sub_session_param['Packets']
                elif sub_session_param['Dir'] == 'Out':
                    sub_session_params['Bytes transmitted total'] = sub_session_param['Bytes']
                    sub_session_params['Packets transmitted total'] = sub_session_param['Packets']
            sub_session_params.pop('Accounting')
            for sub_session_param in sub_session_params['Policing']:
                if sub_session_param['Dir'] == 'In':
                    sub_session_params['Maximum data rate downstream total'] = str(
                        int(sub_session_param['Avg. Rate']) // 1000) + ' Kb/s'
                elif sub_session_param['Dir'] == 'Out':
                    sub_session_params['Maximum data rate upstream total'] = str(
                        int(sub_session_param['Avg. Rate']) // 1000) + ' Kb/s'
            sub_session_params.pop('Policing')
        else:
            sub_session_params['Status'] = 'Not found'
            sub_session_params['ActionStatus'] = 'Failed'
        p.sendline('exit')
        p.expect(['>', pexpect.EOF, pexpect.TIMEOUT])
        p.close()

        sub_session_params['Action'] = action
        sub_session_params['NAS'] = 'ISG'
        sub_session_params['Idle timeout expires in'] = 'Not defined'
        sub_session_params['Interim interval expires in'] = 'Not defined'
        sub_session_params['Session timeout expires in'] = 'Not defined'
        return sub_session_params
    if action == 'clear':
        p.sendline('show subscriber session identifier source-ip-address ' + sub_ip + ' 255.255.255.255')
        result = p.expect(['>', pexpect.EOF, pexpect.TIMEOUT])
        if result == 1 or result == 2:
            logger.error("Failed  to get subscriber session " + sub_ip)
            p.close()
            return 500
        sub_session_info = p.before.splitlines()[1:-1]
        sub_session_params = {}
        for sub_session_str in sub_session_info:
            if not sub_session_str:
                continue
            if 'Type:' in sub_session_str:
                sub_session_str_split = sub_session_str.split(',')
                for sub_session_str_hash in sub_session_str_split:
                    [key, value] = sub_session_str_hash.split(':')
                    sub_session_params[key.strip()] = value.strip()
            elif 'IPv4 Address:' in sub_session_str or 'Switch-ID' in sub_session_str:
                [key, value] = sub_session_str.split(':')
                sub_session_params[key.strip()] = value.strip()
            elif 'Session Up-time:' in sub_session_str:
                sub_session_str_split = sub_session_str.split(',')
                for sub_session_str_hash in sub_session_str_split:
                    [key, value] = sub_session_str_hash.split(':', 1)
                    sub_session_params[key.strip()] = value.strip()
            elif 'Policy information:' in sub_session_str:
                break
        if sub_session_params:
            p.sendline('clear subscriber session uid ' + sub_session_params['UID'])
            result = p.expect(['>', pexpect.EOF, pexpect.TIMEOUT])
            if result == 1 or result == 2:
                logger.error("Failed  to exit" + nas_ip)
                p.close()
                return 500
            sub_session_params['ActionStatus'] = 'Success'
            sub_session_params.pop('Type')
            sub_session_params.pop('UID')
            if sub_session_params['State'] == 'authen':
                sub_session_params.pop('State')
                sub_session_params['Status'] = 'Authorized'
            sub_session_params.pop('Identity')
            sub_session_params['Subscriber'] = sub_session_params.pop('IPv4 Address')
            sub_session_params.pop('Switch-ID')
        else:
            sub_session_params['Status'] = 'Not Found'
            sub_session_params['ActionStatus'] = 'Failed'
        p.sendline('exit')
        p.expect(['>', pexpect.EOF, pexpect.TIMEOUT])
        p.close()
        sub_session_params['Action'] = action
        sub_session_params['NAS'] = 'ISG'
        sub_session_params['Idle timeout expires in'] = 'Not defined'
        sub_session_params['Interim interval expires in'] = 'Not defined'
        sub_session_params['Session timeout expires in'] = 'Not defined'
        return sub_session_params


def asrSubSessionActionsOld(nas_ip, sub_ip, action, logger, login, password):
    p = pexpect.spawn('telnet %s' % nas_ip, timeout=5, encoding='utf-8')
    p.setwinsize(80, 40)
    result = p.expect(['Username:', pexpect.EOF, pexpect.TIMEOUT])
    if result == 1 or result == 2:
        logger.error("Failed  to connect " + nas_ip)
        p.close()
        return 404
    p.sendline(login)
    p.expect(['Password:'])
    p.sendline(password)
    result = p.expect(['>', pexpect.EOF, pexpect.TIMEOUT])
    if result == 1 or result == 2:
        logger.error("Failed  to login " + nas_ip)
        p.close()
        return 403
    if action == 'show':
        p.sendline('show subscriber session identifier source-ip-address ' + sub_ip + ' 255.255.255.255')
        result = p.expect(['>', pexpect.EOF, pexpect.TIMEOUT])
        if result == 1 or result == 2:
            logger.error("Failed  to get subscriber session " + sub_ip)
            p.close()
            return 402
        sub_session_info = p.before.splitlines()[1:-1]

        sub_session_params = {}
        sub_session_parser_flag = 0

        print(sub_session_info)

        for sub_session_str in sub_session_info:
            if not sub_session_str:
                continue
            if sub_session_parser_flag == 0:
                if 'Identifier:' in sub_session_str:
                    [key, value] = sub_session_str.split(':')
                    sub_session_params[key.strip()] = value.strip()
                elif 'Authentication status:' in sub_session_str:
                    [key, value] = sub_session_str.split(':')
                    sub_session_params[key.strip()] = value.strip()
                elif 'Session Up-time:' in sub_session_str:
                    sub_session_str_split = sub_session_str.split(',')
                    for sub_session_str_hash in sub_session_str_split:
                        [key, value] = sub_session_str_hash.split(':', 1)
                        sub_session_params[key.strip()] = value.strip()
                elif 'Rules, actions and conditions executed:' in sub_session_str:
                    sub_session_parser_flag = 1
            elif sub_session_parser_flag == 1:
                if 'Session inbound features:' in sub_session_str:
                    sub_session_parser_flag = 2
                    sub_session_inbound = {}
            elif sub_session_parser_flag == 2:
                if 'Session outbound features:' in sub_session_str:
                    sub_session_parser_flag = 3
                    sub_session_outbound = {}
                else:
                    if 'Packets' in sub_session_str:
                        sub_session_str_split = sub_session_str.split(', ')
                        for sub_session_str_hash in sub_session_str_split:
                            [key, value] = sub_session_str_hash.split(' = ')
                            sub_session_inbound[key.strip()] = value.strip()
                    elif 'Average rate' in sub_session_str:
                        sub_session_str_split = sub_session_str.split(', ')
                        for sub_session_str_hash in sub_session_str_split:
                            [key, value] = sub_session_str_hash.split(' = ')
                            sub_session_inbound[key.strip()] = value.strip()
            elif sub_session_parser_flag == 3:
                if 'Configuration sources associated with this session:' in sub_session_str:
                    break
                else:
                    if 'Packets' in sub_session_str:
                        sub_session_str_split = sub_session_str.split(',')
                        for sub_session_str_hash in sub_session_str_split:
                            [key, value] = sub_session_str_hash.split(' = ')
                            sub_session_outbound[key.strip()] = value.strip()
                    elif 'Average rate' in sub_session_str:
                        sub_session_str_split = sub_session_str.split(',')
                        for sub_session_str_hash in sub_session_str_split:
                            [key, value] = sub_session_str_hash.split(' = ')
                            sub_session_outbound[key.strip()] = value.strip()

        if sub_session_inbound:
            if sub_session_inbound['Packets']:
                sub_session_params['Packets recieved total'] = sub_session_inbound['Packets']
            if sub_session_inbound['Bytes']:
                sub_session_params['Bytes recieved total'] = sub_session_inbound['Bytes']
            if sub_session_inbound['Average rate']:
                sub_session_params['Maximum data rate downstream total'] = str(
                    int(sub_session_inbound['Average rate']) // 1000) + ' Kb/s'

        if sub_session_outbound:
            if sub_session_outbound['Packets']:
                sub_session_params['Packets transmitted total'] = sub_session_outbound['Packets']
            if sub_session_inbound['Bytes']:
                sub_session_params['Bytes transmitted total'] = sub_session_outbound['Bytes']
            if sub_session_inbound['Average rate']:
                sub_session_params['Maximum data rate upstream total'] = str(
                    int(sub_session_inbound['Average rate']) // 1000) + ' Kb/s'

        if sub_session_params:
            sub_session_params['ActionStatus'] = 'Success'
            if sub_session_params['Authentication status'] == 'authen':
                sub_session_params.pop('Authentication status')
                sub_session_params['Status'] = 'Authorized'
            sub_session_params.pop('Identifier')
            sub_session_params['Subscriber'] = 'Not defined'
        else:
            sub_session_params['Status'] = 'Not found'
            sub_session_params['ActionStatus'] = 'Failed'
        p.sendline('exit')
        p.expect(['>', pexpect.EOF, pexpect.TIMEOUT])
        p.close()

        sub_session_params['Action'] = action
        sub_session_params['NAS'] = 'ISG old'
        sub_session_params['Idle timeout expires in'] = 'Not defined'
        sub_session_params['Interim interval expires in'] = 'Not defined'
        sub_session_params['Session timeout expires in'] = 'Not defined'

        print(sub_session_params)

        return sub_session_params
    if action == 'clear':
        p.sendline('show subscriber session identifier source-ip-address ' + sub_ip + ' 255.255.255.255')
        result = p.expect(['>', pexpect.EOF, pexpect.TIMEOUT])
        if result == 1 or result == 2:
            logger.error("Failed  to get subscriber session " + sub_ip)
            p.close()
            return 500
        sub_session_info = p.before.splitlines()[1:-1]
        sub_session_params = {}
        for sub_session_str in sub_session_info:
            if not sub_session_str:
                continue
            if 'Type:' in sub_session_str:
                sub_session_str_split = sub_session_str.split(',')
                for sub_session_str_hash in sub_session_str_split:
                    [key, value] = sub_session_str_hash.split(':')
                    sub_session_params[key.strip()] = value.strip()
            elif 'IPv4 Address:' in sub_session_str or 'Switch-ID' in sub_session_str:
                [key, value] = sub_session_str.split(':')
                sub_session_params[key.strip()] = value.strip()
            elif 'Session Up-time:' in sub_session_str:
                sub_session_str_split = sub_session_str.split(',')
                for sub_session_str_hash in sub_session_str_split:
                    [key, value] = sub_session_str_hash.split(':', 1)
                    sub_session_params[key.strip()] = value.strip()
#pycek
            elif 'Unique Session ID:' in sub_session_str:
                sub_session_params['UID'] = sub_session_str.split(':')[1]
            elif 'Policy information:' in sub_session_str:
                break
        if sub_session_params:
            p.sendline('clear subscriber session uid ' + sub_session_params['UID'])
            result = p.expect(['>', pexpect.EOF, pexpect.TIMEOUT])
            if result == 1 or result == 2:
                logger.error("Failed  to exit" + nas_ip)
                p.close()
                return 500
            sub_session_params['ActionStatus'] = 'Success'
            sub_session_params.pop('Type')
            sub_session_params.pop('UID')
            if sub_session_params['State'] == 'authen':
                sub_session_params.pop('State')
                sub_session_params['Status'] = 'Authorized'
            sub_session_params.pop('Identity')
            sub_session_params['Subscriber'] = sub_session_params.pop('IPv4 Address')
            sub_session_params.pop('Switch-ID')
        else:
            sub_session_params['Status'] = 'Not Found'
            sub_session_params['ActionStatus'] = 'Failed'
        p.sendline('exit')
        p.expect(['>', pexpect.EOF, pexpect.TIMEOUT])
        p.close()
        sub_session_params['Action'] = action
        sub_session_params['NAS'] = 'ISG'
        sub_session_params['Idle timeout expires in'] = 'Not defined'
        sub_session_params['Interim interval expires in'] = 'Not defined'
        sub_session_params['Session timeout expires in'] = 'Not defined'
        return sub_session_params


def econatSubSessionActions(nas_ip, sub_ip, action, logger, login, password):
    p = pexpect.spawn('ssh %s@%s interactive' % (login, nas_ip), timeout=5, encoding='utf-8')
    while True:
        result = p.expect(
            ['Password:', 'Are you sure you want to continue connecting (yes/no)?', pexpect.EOF, pexpect.TIMEOUT])
        if result == 0:
            p.sendline(password)
            break
        elif result == 1:
            p.sendline('yes')
            continue
        else:
            logger.error("Failed  to login " + nas_ip)
            p.close()
            return 403

    result = p.expect(['>', pexpect.EOF, pexpect.TIMEOUT])
    if result == 1 or result == 2:
        logger.error("Failed  to login " + nas_ip)
        p.close()
        return 403
    p.sendline('configure')
    result = p.expect(['#', pexpect.EOF, pexpect.TIMEOUT])
    if result == 1 or result == 2:
        logger.error("Failed  to login " + nas_ip)
        p.close()
        return 403
    if action == 'show':
        p.sendline('show brasinfo ' + sub_ip)
        result = p.expect(['#', pexpect.EOF, pexpect.TIMEOUT])
        if result == 1 or result == 2:
            logger.error("Failed  to login " + nas_ip)
            p.close()
            return 500
        sub_session_info = p.before.splitlines()[2:-1]
        
        sub_session_params = {}
        sub_session_parser_flag = 0
        #        sub_session_params['NASip'] = nas_ip.split('.')[3]
        for sub_session_str in sub_session_info:
            if not sub_session_str:
                continue
            if 'not found' in sub_session_str:
                sub_session_params['Subscriber'] = sub_ip
                sub_session_params['Status'] = 'Not found'
                sub_session_params['ActionStatus'] = 'Failed'
                sub_session_params['Action'] = action
                break
            if '===' in sub_session_str:
                sub_session_parser_flag = sub_session_parser_flag + 1
                continue
            if '---' in sub_session_str:
                sub_session_params['ActionStatus'] = 'Success'
                sub_session_params['Action'] = action
                sub_session_parser_flag = sub_session_parser_flag + 1
            if '1. service' in sub_session_str:
                sub_session_params['Service1'] = sub_session_str.split(' ')[1]
                break
            if sub_session_parser_flag == 1:
                [key, value] = sub_session_str.split(' ')
                sub_session_params[key] = value
            if sub_session_parser_flag == 2:
                sub_session_str = re.sub('\s\s+', '  ', sub_session_str)
                [key, value] = sub_session_str.split('  ')
                sub_session_params[key] = value
        if "Idle timeout expires in" in sub_session_params.keys():
            sub_session_params["Idle timeout expires in"] = sec2hours(sub_session_params["Idle timeout expires in"])
        if "Interim interval expires in" in sub_session_params.keys():
            sub_session_params["Interim interval expires in"] = sec2hours(
                sub_session_params["Interim interval expires in"])
        if "Session timeout expires in" in sub_session_params.keys():
            sub_session_params["Session timeout expires in"] = sec2hours(
                sub_session_params["Session timeout expires in"])
        sub_session_params['NAS'] = 'NAT-' + nas_ip.split('.')[3]
        sub_session_params['Session Up-time'] = 'Not defined'
        sub_session_params['Last Changed'] = 'Not defined'
        p.close()
        return sub_session_params
    if action == 'clear':
        p.sendline('show brasinfo ' + sub_ip)
        result = p.expect(['#', pexpect.EOF, pexpect.TIMEOUT])
#        logger.error("not sub_session_str1" + result)
        if result == 1 or result == 2:
            logger.error("Failed  to login " + nas_ip)
            p.close()
            return 500
#        logger.error("not sub_session_str1" + sub_session_info)
        sub_session_info = p.before.splitlines()[2:-1]
        sub_session_params = {}
        sub_session_parser_flag = 0
        for sub_session_str in sub_session_info:
            if not sub_session_str:
#                logger.error("not sub_session_str1" + ' '.join([str(elem) for elem in sub_session_info]))
                continue
            if 'not found' in sub_session_str:
                break
            if '===' in sub_session_str:
                sub_session_parser_flag = sub_session_parser_flag + 1
                continue
            if '---' in sub_session_str:
                break
            if sub_session_parser_flag == 1:
                [key, value] = sub_session_str.split(' ')
                sub_session_params[key] = value
            if sub_session_parser_flag == 2:
                sub_session_str = re.sub('\s\s+', '  ', sub_session_str)
                [key, value] = sub_session_str.split('  ')
                sub_session_params[key] = value
        p.sendline('clear brasinfo ' + sub_ip)
        result = p.expect(['#', pexpect.EOF, pexpect.TIMEOUT])
        if result == 1 or result == 2:
            logger.error("Failed  to login " + nas_ip)
            p.close()
            return 500
        sub_session_clear = p.before.splitlines()[2:-1]
#        logger.error("not sub_session_str1" + ' '.join([str(elem) for elem in sub_session_clear]))
        for sub_session_str in sub_session_clear:
            if not sub_session_str:
                logger.error("not sub_session_str222" + sub_session_str)
                continue
            if 'Failed to clear ip' in sub_session_str:
                sub_session_params['Subscriber'] = sub_ip
                sub_session_params['Status'] = 'Not found'
                sub_session_params['ActionStatus'] = 'Failed'
            if 'Success' in sub_session_str:
                sub_session_params['ActionStatus'] = 'Success'
        sub_session_params['Action'] = action
        sub_session_params['NAS'] = 'NAT'
        sub_session_params['Session Up-time'] = 'Not defined'
        sub_session_params['Last Changed'] = 'Not defined'
        p.close()
        return sub_session_params


def session(nas_ip, sub_ip, sub_net, action):
    dictLogConfig = {
        "version": 1,
        "handlers": {
            "fileHandler": {
                "class": "logging.FileHandler",
                "formatter": "myFormatter",
                "filename": "sub_session_actions.log"
            }
        },
        "loggers": {
            "loggerApp": {
                "handlers": ["fileHandler"],
                "level": "INFO",
            }
        },
        "formatters": {
            "myFormatter": {
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(nas_ip)s - %(sub_ip)s/%(sub_net)s - %(message)s"
            }
        }
    }

    logging.config.dictConfig(dictLogConfig)
    logger = logging.getLogger("loggerApp")

    extra = {
        'nas_ip': nas_ip,
        'sub_ip': sub_ip,
        'sub_net': sub_net,
    }

    logger = logging.LoggerAdapter(logger, extra)

    logger.info("request " + action)

    nas_type = {
        '172.26.0.101': 3,
        '172.26.0.105': 1,
        '172.26.0.109': 1,
        '172.26.0.113': 1,
        '172.26.0.117': 1,
        '10.244.2.151': 2,
        '10.244.2.152': 2,
        '10.244.2.153': 2,
        '10.244.2.154': 2,
    }

    if sub_net == "32":
        ips = list(ip_network(sub_ip + "/" + sub_net))
    else:
        ips = list(ip_network(sub_ip + "/" + sub_net).hosts())

    if nas_ip in nas_type:
        if nas_type[nas_ip] == 1:
            for ip in ips:
                ip = str(ip)
                nas_login = 'script'
                nas_password = 'OhKRKjvF46'
                result = asrSubSessionActions(nas_ip, ip, action, logger, nas_login, nas_password)
                if result["ActionStatus"] == "Failed":
                    continue
                else:
                    break
            addPlaceHolders(result)
            logger.info("result " + str(result))
            
            return result
        elif nas_type[nas_ip] == 3:
            for ip in ips:
                ip = str(ip)
                nas_login = 'script'
                nas_password = 'OhKRKjvF46'
                result = asrSubSessionActionsOld(nas_ip, ip, action, logger, nas_login, nas_password)
                if result["ActionStatus"] == "Failed":
                    continue
                else:
                    break
            addPlaceHolders(result)
            logger.info("result " + str(result))
            
            return result
        elif nas_type[nas_ip] == 2:
            for ip in ips:
                ip = str(ip)
                nas_login = 'script'
                nas_password = 'oBmb04Sr3I'
                result = econatSubSessionActions(nas_ip, ip, action, logger, nas_login, nas_password)
                if result["ActionStatus"] == "Failed":
                    continue
                else:
                    break
            addPlaceHolders(result)
            logger.info("result " + str(result))
            
            return result
    else:
        logger.error("Unknown NAS " + nas_ip)
        return 400


if __name__ == '__main__':
    nas_ip = sys.argv[1]
    sub_ip = sys.argv[2]
    sub_net = sys.argv[3]
    action = sys.argv[4]
    result = session(nas_ip, sub_ip, sub_net, action)
    print(result)
