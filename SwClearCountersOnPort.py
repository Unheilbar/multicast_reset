import pexpect

def getSwitchModel(sw_ip, login, password):
    p = pexpect.spawn('telnet %s' % sw_ip, timeout=5, encoding='utf-8')
    result = p.expect(['UserName:', pexpect.EOF, pexpect.TIMEOUT])
    
    if(result != 0):
        print("Failed  to connect " + sw_ip)
        p.close()
    
    p.sendline(login)
    p.expect(['Password:'])
    p.sendline(password)
    result = p.expect(['#', pexpect.EOF, pexpect.TIMEOUT])
    
    if(result != 0):
        print("Login error on " + sw_ip)
        p.close()
    

    p.sendline('show switch')
    p.expect('MAC Address')
    info = p.before
    p.close()
    return result    

result = getSwitchModel('10.240.12.184', 'admin', 'JyNa7D')
switches = ['X9HRhz', '10.240.1.253']
print(result)