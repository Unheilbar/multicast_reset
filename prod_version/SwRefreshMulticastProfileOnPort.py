import pexpect
import sys

def getSwitchModel(p, res):
    p.sendline('show switch')
    result = p.expect(['MAC Address', pexpect.EOF, pexpect.TIMEOUT])
    if result != 0:
        p.close()
        res = {
            'status' : '404',
            'error_message' : 'device is not found'
        }
        return
    
    info = p.before.splitlines()
    for line in info:
        if ':' in line:
            [key, value] = (x.strip() for x in line.split(':'))
            if key == 'Device Type':
                return value.split()[0]

def authOnSwitch(sw_ip, login, password, port):
    p = pexpect.spawn('telnet %s' % sw_ip, timeout=5, encoding='utf-8')
    result = p.expect(['Username', 'UserName:', 'username', pexpect.EOF, pexpect.TIMEOUT])
    
    if result == 3 or result == 4:
        p.close()
        res = {
            'status' : '503',
            'error_message' : 'Switch is unavailable'
        }
        return
    
    p.sendline(login)
    result = p.expect(['Password:', 'PassWord', 'password', pexpect.EOF, pexpect.TIMEOUT])
    p.sendline(password)
    result = p.expect(['#', pexpect.EOF, pexpect.TIMEOUT])
    if result == 1 or result == 2:
        res = {
            'status' : '401',
            'error_message' : 'Authorization failed'
        }

        return
    
    return p




def refreshMulticastProfileOnPort(sw_ip, login, password, port):
    res = {}

    p = authOnSwitch(sw_ip, login, password, port)

    if 'error_message' in res:
        return res
        

    device  = getSwitchModel(p, res)
    
    if 'error_message' in res:
        return res

    command_patterns = [
        {
            'device' : '''
                DGS-1210-52/ME-B
                DGS-1210-28/ME-B
                DGS-1210-52/ME
                DES-3200-28
                DES-3200-52
            ''',
            'command_delete' : 'config limited_multicast_addr ports %s ipv4 delete profile_id %s',
            'command_add' : 'config limited_multicast_addr ports %s ipv4 add profile_id %s'
        
        },
        {
            'device' : 'DES-3526',
            'command_delete' : 'config limited_multicast_addr ports %s delete multicast_range %s',
            'command_add' : 'config limited_multicast_addr ports %s add multicast_range %s'
        },
        {
            'device' : 'DES-3028 DES-3028G',
            'command_delete' : 'config limited_multicast_addr ports %s delete profile_id %s',
            'command_add' : 'config limited_multicast_addr ports %s add profile_id %s'
        }
    ]

    device_detected = False
    for pattern in command_patterns:
        if device in pattern['device']:
            device_detected = True
            for id in range(1, 9):
                p.sendline(pattern['command_delete']%(port,id))
                result = p.expect(['Success', 'success', pexpect.EOF, pexpect.TIMEOUT])
                if result == 2 or result == 3:
                    res = {
                        'status' : '405',
                        'error_message' : 'Invalid command executed'
                    }
                    return res
                
                p.sendline(pattern['command_add']%(port,id))
                result = p.expect(['Success', 'success', pexpect.EOF, pexpect.TIMEOUT])
                if result == 2 or result == 3:
                    res = {
                        'status' : '405',
                        'error_message' : 'Invalid command executed'
                    }
                    return res
            break

    if not device_detected:
        p.close()
        res = {
            'status' : '404',
            'error_message' : 'device is not found'
        }
        return res
    else:
        res = {
            'status' : '200',
            'data' : 'ok'
        }
        p.close()
        return res

if __name__ == '__main__':
    sw_ip = sys.argv[1]
    login = sys.argv[2]
    password = sys.argv[3]
    port = sys.argv[4]
    result = refreshMulticastProfileOnPort(sw_ip, login, password, port)
    print(result)

