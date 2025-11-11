import subprocess

binary = "./main"  # hoặc lấy từ sys.argv[1] nếu muốn dynamic
output_file = "results.txt"

with open(output_file, "w") as f_out:
    for i in range(20):
        filename = f"test_{i:02d}.inp"
        try:
            # Chạy chương trình
            result = subprocess.run(
                [binary, filename],
                capture_output=True,
                text=True,
                timeout=60
            )

            # Chuẩn bị kết quả
            out_text = f"{filename}:\n{result.stdout.strip()}"
            if result.stderr:
                out_text += f"\nError: {result.stderr.strip()}"
            out_text += "\n" + "-"*40 + "\n"

            # In ra màn hình
            print(out_text)
            # Ghi vào file
            f_out.write(out_text)

        except FileNotFoundError:
            err_text = f"{filename} not found!\n" + "-"*40 + "\n"
            print(err_text)
            f_out.write(err_text)
        except subprocess.TimeoutExpired:
            err_text = f"Timeout expired for {filename}\n" + "-"*40 + "\n"
            print(err_text)
            f_out.write(err_text)

print(f"All results saved to {output_file}")
