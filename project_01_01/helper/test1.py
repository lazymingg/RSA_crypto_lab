import subprocess
import time
from pathlib import Path

# Lấy đường dẫn thư mục hiện tại của file Python
base_dir = Path(__file__).resolve().parent.parent  # helper/.. -> project_01_01

binary = base_dir / "main"
test_dir = base_dir / "test"
output_file = base_dir / "results.txt"

start_all = time.time()

with open(output_file, "w") as f_out:
    for i in range(20):
        filename = test_dir / f"test_{i:02d}.inp"
        start = time.time()
        try:
            # Chạy chương trình
            result = subprocess.run(
                [str(binary), str(filename)],
                capture_output=True,
                text=True,
                timeout=60
            )
            end = time.time()
            elapsed = end - start

            # Chuẩn bị kết quả
            out_text = f"{filename.name}:\n{result.stdout.strip()}"
            if result.stderr:
                out_text += f"\nError: {result.stderr.strip()}"
            out_text += f"\nTime: {elapsed:.4f} seconds\n" + "-"*40 + "\n"

            print(out_text)
            f_out.write(out_text)

        except FileNotFoundError:
            end = time.time()
            elapsed = end - start
            err_text = f"{filename.name} not found!\nTime: {elapsed:.4f} seconds\n" + "-"*40 + "\n"
            print(err_text)
            f_out.write(err_text)
        except subprocess.TimeoutExpired:
            end = time.time()
            elapsed = end - start
            err_text = f"Timeout expired for {filename.name}\nTime: {elapsed:.4f} seconds\n" + "-"*40 + "\n"
            print(err_text)
            f_out.write(err_text)

end_all = time.time()
total_time = end_all - start_all
print(f"All results saved to {output_file}")
print(f"Total elapsed time: {total_time:.4f} seconds")
