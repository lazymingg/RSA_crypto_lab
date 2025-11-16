from pwn import *
import time
from pathlib import Path

# Thư mục project và binary
base_dir = Path('.')
binary = base_dir / 'main'
test_dir = base_dir / 'test'
output_file = base_dir / 'results.txt'

ntest = 20  # số test case
start_all = time.time()

with open(output_file, 'w') as f_out:
    for i in range(ntest):
        test_inp = test_dir / f'test_{i:02d}.inp'
        start = time.time()
        try:
            # Chạy process
            p = process([str(binary), str(test_inp)], display=False)
            stdout = p.recvall(timeout=60).decode(errors='ignore').strip()
            end = time.time()
            elapsed = end - start

            got = stdout.upper()
            
            # Nếu có file .out thì đọc expected
            test_out_file = test_dir / f'test_{i:02d}.out'
            if test_out_file.exists():
                with open(test_out_file, 'r') as f:
                    expected = f.read().strip().upper()
                status = 'PASS' if got == expected else 'FAIL'
            else:
                expected = 'N/A'
                status = 'DONE'

            # Chuẩn bị text
            out_text = (
                f"Test case {i:02d}:\n"
                f"Input: {test_inp.name}\n"
                f"Expected: {expected}\n"
                f"Got: {got}\n"
                f"Status: {status}\n"
                f"Runtime: {elapsed:.4f} s\n"
                + '-'*40 + '\n'
            )
            print(out_text)
            f_out.write(out_text)

        except FileNotFoundError:
            end = time.time()
            elapsed = end - start
            err_text = f"{test_inp.name} not found! | Time: {elapsed:.4f} s\n" + '-'*40 + '\n'
            print(err_text)
            f_out.write(err_text)
        except Exception as e:
            end = time.time()
            elapsed = end - start
            err_text = f"Error with {test_inp.name}: {str(e)} | Time: {elapsed:.4f} s\n" + '-'*40 + '\n'
            print(err_text)
            f_out.write(err_text)

end_all = time.time()
total_time = end_all - start_all
print(f"All results saved to {output_file}")
print(f"Total elapsed time: {total_time:.4f} s")
