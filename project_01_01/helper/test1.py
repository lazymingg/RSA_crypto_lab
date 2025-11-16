from pwn import *
import time
from pathlib import Path

# Thư mục project và binary
base_dir = Path('.')
binary = base_dir / 'main'
test_dir = base_dir / 'test'
out_dir = test_dir / 'out'      # thư mục chứa file .out tự tạo
output_file = base_dir / 'results.txt'

# Tạo thư mục out nếu chưa có
out_dir.mkdir(exist_ok=True)

ntest = 20
start_all = time.time()

with open(output_file, 'w') as f_out:
    for i in range(ntest):

        inp_file = test_dir / f'test_{i:02d}.inp'
        out_expected = test_dir / f'test_{i:02d}.out'      # file .out gốc nếu có
        out_auto = out_dir / f'test_{i:02d}.out'           # file .out tự tạo khi không có gốc

        # -------------------------------
        # Chọn nơi ghi output:
        # - Nếu có file expected → chạy vào expected
        # - Nếu không có → chạy vào out/test_XX.out
        # -------------------------------
        if out_expected.exists():
            out_file_for_program = out_expected
        else:
            out_file_for_program = out_auto

        start = time.time()

        try:
            # Xóa file output cũ trước khi chạy
            if out_file_for_program.exists():
                out_file_for_program.unlink()

            # Chạy chương trình: ./main input output
            p = process([
                str(binary),
                str(inp_file),
                str(out_file_for_program)
            ], display=False)

            p.wait_for_close(timeout=60)
            end = time.time()
            elapsed = end - start

            # Đọc file output sau khi chương trình chạy
            if out_file_for_program.exists():
                got = out_file_for_program.read_text().strip().upper()
            else:
                got = ""
                raise Exception("Output file not generated")

            # Nếu có expected → so sánh
            if out_expected.exists():
                expected = out_expected.read_text().strip().upper()
                status = "PASS" if got == expected else "FAIL"
            else:
                # Không có expected → file này được xem như file mới
                expected = "N/A"
                status = "CREATED"

            # Ghi log
            out_text = (
                f"Test case {i:02d}:\n"
                f"Input: {inp_file.name}\n"
                f"Expected: {expected}\n"
                f"Got: {got}\n"
                f"Status: {status}\n"
                f"Runtime: {elapsed:.4f} s\n"
                + '-' * 40 + '\n'
            )

            print(out_text)
            f_out.write(out_text)

        except Exception as e:
            end = time.time()
            elapsed = end - start
            err_text = (
                f"Error with {inp_file.name}: {e} | Time: {elapsed:.4f} s\n"
                + '-' * 40 + '\n'
            )
            print(err_text)
            f_out.write(err_text)

end_all = time.time()
total_time = end_all - start_all
print(f"All results saved to {output_file}")
print(f"Total elapsed time: {total_time:.4f} s")
