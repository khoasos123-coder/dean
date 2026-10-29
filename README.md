# Wrote M1n10n_53cr37_writeup.md
# M1n10n'5_53cr37 — Writeup

## Thông tin challenge

- **Tên:** M1n10n'5_53cr37
- **Thể loại:** Reverse Engineering
- **File:** Minions Mobile Application (APK)


## Các bước làm

### 1. Decompile APK

Dùng jadx-gui:

```bash
jadx-gui Minions.apk
```

Hoặc dùng apktool:

```bash
apktool d Minions.apk -o minions_decoded
```

### 2. Tìm dấu vết flag

Trong app có gợi ý liên quan đến **Banana**. Tìm trong resource:

```bash
grep -ri "banana" minions_decoded
```

Kết quả là một string resource tên `Banana` chứa chuỗi:

```text
OBUWG32DKRDHWMLUL53TI43OG5PWQNDSMRPXK3TSGR3DG3BRNY4V65DIGNPW2MDCGFWDGX3DGBSDG7I=
```

Chuỗi chỉ gồm `A-Z` và `2-7`, kết thúc bằng `=` → đây là **Base32**.

### 3. Decode Base32

Dùng Python:

```bash
python -c "import base64; s='OBUWG32DKRDHWMLUL53TI43OG5PWQNDSMRPXK3TSGR3DG3BRNY4V65DIGNPW2MDCGFWDGX3DGBSDG7I='; print(base64.b32decode(s).decode())"
```

Hoặc trên Linux:

```bash
echo "OBUWG32DKRDHWMLUL53TI43OG5PWQNDSMRPXK3TSGR3DG3BRNY4V65DIGNPW2MDCGFWDGX3DGBSDG7I=" | base32 -d
```

## Flag

```text
picoCTF{1t_w4sn7_h4rd_unr4v3l1n9_th3_m0b1l3_c0d3}
```

## Kết luận

Flag được giấu dưới dạng chuỗi **Base32** trong resource của APK. Chỉ cần decompile, tìm string đáng ngờ và decode là có flag.
