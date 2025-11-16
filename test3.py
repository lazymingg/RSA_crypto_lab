from pwn import *

context.binary = './project_01_03/main'
dir = './project_01_03/'

ntest = 10
for i in range(ntest):
    p = process([dir + 'main', dir + f'test_{i:02d}.inp'])
    stdout = p.recvall(timeout=30).decode(errors='ignore')[:-1]
    print("")

    got = stdout.upper()
    print('Got:', got)

    with open(dir + f'test_{i:02d}.out', 'r') as f:
        expected = f.read().strip().upper()
    print('Expected:', expected)
    
    print(f'Test case {i}: ', end='')
    print('PASS' if got == expected else 'FAIL')
    print('--------------------')
