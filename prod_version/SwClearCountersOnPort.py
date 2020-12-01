import pexpect
import sys

def clearCountersOnPort(sw_ip, login, password, port):
    p = pexpect.spawn('telnet %s' % sw_ip, timeout=5, encoding='utf-8')
    result = p.expect(['Username', 'UserName:', 'username', pexpect.EOF, pexpect.TIMEOUT])

    if result == 3 or result == 4:
        p.close()
        res = {
            'status' : '503',
            'error_message' : 'Switch is unavailable'
        }
        return res
    
    p.sendline(login)
    result = p.expect(['Password:', 'PassWord', 'password', pexpect.EOF, pexpect.TIMEOUT])
    p.sendline(password)
    result = p.expect(['#', pexpect.EOF, pexpect.TIMEOUT])

    if result == 1 or result == 2:
        p.close()
        res = {
            'status' : '401',
            'error_message' : 'Authorization failed'
        }

        return res
    
    p.sendline('clear counters ports %s'%port)
    result = p.expect(['Success', 'success', pexpect.EOF, pexpect.TIMEOUT])

    if result == 2 or result == 3:
        p.close()
        res = {
            'status' : '405',
            'error_message' : 'Invalid command executed'
        }
        return res
    
    p.close()

    res = {
        'status' : '200',
        'data' : 'ok'
    }

    return(res)

if __name__ == '__main__':
    sw_ip = sys.argv[1]
    login = sys.argv[2]
    password = sys.argv[3]
    port = sys.argv[4]
    result = clearCountersOnPort(sw_ip, login, password, port)

    print(result)
