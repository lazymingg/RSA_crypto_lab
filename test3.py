from pwn import *
import os

context.binary = './project_01_03/main'
dir = './project_01_03/'

ntest = 10
for i in range(ntest):
    output_file = f'temp_output_{i:02d}.txt'
    
    p = process([dir + 'main', dir + f'test_{i:02d}.inp', output_file])
    p.wait()
    
    try:
        with open(output_file, 'r') as f:
            got = f.read().strip().upper()
    except:
        got = ""
    
    print("")
    print('Got:', got)

    with open(dir + f'test_{i:02d}.out', 'r') as f:
        expected = f.read().strip().upper()
    print('Expected:', expected)
    
    print(f'Test case {i}: ', end='')
    print('PASS' if got == expected else 'FAIL')
    print('--------------------')
    
    if os.path.exists(output_file):
        os.remove(output_file)
