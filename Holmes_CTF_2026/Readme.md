# Write-up: Scenario 1 - SilentDividend (Holmes CTF 2026)

## 1. Tổng quan thử thách
* **Môi trường:** Ứng dụng Desktop viết bằng Electron (bao gồm file `.exe` và `app-64.7z` chứa `app.asar`).
* **Hành vi:** Phần mềm độc hại mô phỏng infostealer kết hợp giữa tập lệnh LuaJIT FFI (gọi Win32 API trên Windows) và Smart Contract trên mạng Sepolia (Ethereum) để quản lý khóa và giải mã payload.



## 2. Chi tiết các câu hỏi

### Câu 1: To which directory does the application copy the files bundled within the extraResources folder?
* **Phân tích:** Giải nén `app.asar`:


<img width="630" height="300" alt="image" src="https://github.com/user-attachments/assets/d9325a48-18a0-481b-a9ca-957e68d0ea3f" />


Kiểm tra source code JavaScript trong thư mục giải nén:
<img width="653" height="502" alt="image" src="https://github.com/user-attachments/assets/b3bfc873-7599-4f07-82ac-35399061cb2b" />

```javascript
fs.readdirSync(path.resolve(`${process.resourcesPath}/../extraResources`)).forEach(f => 
    fs.copyFileSync(path.resolve(`${process.resourcesPath}/../extraResources`, f), path.join('C:\\Users\\Public', f))
);

```
* **Đáp án:** `C:\Users\Public`



### Câu 2: Which Win32 structure defines the format of the buffer returned by the Lua script when monitoring directory changes?
* **Phân tích:** Tập lệnh LuaJIT (`api.txt`) thực thi qua PowerShell dùng Win32 API `ReadDirectoryChangesW` để giám sát thay đổi tệp tin. Cấu trúc lưu trữ buffer sự kiện trả về của hàm này là `FILE_NOTIFY_INFORMATION`.
* **Đáp án:** `FILE_NOTIFY_INFORMATION`



### Câu 3: Which Win32 API is used by the Lua script to send an HTTP request to the remote server?
* **Phân tích:** Kịch bản Lua FFI load thư viện `wininet.dll` để kết nối gửi dữ liệu về máy chủ C2. Hàm chuẩn để gửi HTTP request là `HttpSendRequestA` (hoặc `HttpSendRequestW`).
* **Đáp án:** `HttpSendRequestA`



### Câu 4: Which smart contract function does the Electron application invoke to retrieve the decryption key for the encrypted payload?
* **Phân tích:** Kiểm tra cấu hình ABI trong mã nguồn Electron:
```javascript
const CONTRACT_ABI = [
    'function resolveState() view returns (bytes32)'
];
```
* **Đáp án:** `resolveState()`



### Câu 5: Investigate the smart contract using its address, analyze its logic, and recover the flag by decoding the encrypted data.
* **Thông tin Smart Contract:**
  * Địa chỉ: `0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1` (Sepolia)
  * Ciphertext Hex: `0x560c325bdd0aeea2cd2690a2ed1c1b4a28deca7ac2a40ce8d2725d539a950ca8f4a4bcf375806c36532258a0cf16c19c12989e0aa0e25a72be241da7d2f74cfa2c4c4e1bbfc6204207fe5c801d201f5af84864f0`
* **Cơ chế giải mã:**
  * Hàm `decryptEmbeddedData` sử dụng Custom XOR với byte magic `0x42` và xoay bit vòng (`rotationBits = 7`).
  * Khóa giải mã `encryptionKey` được lấy từ hàm view `resolveState()` trên Smart Contract.



### Câu 6: Xác định biến môi trường chứa thư mục file tạm
* **Phân tích:** Dựa trên chuỗi lệnh trích xuất: `start "" "%TEMP%\settlement.html"`.
* **Đáp án:** `TEMP` (hoặc `%TEMP%`)



### Câu 7: Tên hàm yêu cầu quyền chi tiêu token (Spending Permission)
* **Phân tích:** Kiểm tra mã nguồn file `settlement.html`, hợp đồng Mock Token thực hiện cấp quyền thông qua hàm ERC-20 chuẩn.
* **Đáp án:** `approve()`



### Câu 8: Lượng token chính xác được truyền vào lệnh approve
* **Phân tích:** Ứng dụng gán quyền chi tiêu tối đa (unlimited allowance) bằng hằng số `ethers.MaxUint256` ($2^{256} - 1$).
* **Đáp án:** `115792089237316195423570985008687907853269984665640564039457584007913129639935`



### Câu 9: Class Provider của Ethers.js v6 kết nối ví trình duyệt
* **Phân tích:** Trong Ethers.js v6, class dùng để bọc provider EIP-1193 từ extension ví thay thế cho `Web3Provider` (v5) là `BrowserProvider`.
* **Đáp án:** `BrowserProvider`



### Câu 10: Phân tích Smart Contract & Khôi phục Flag

#### 1. Thông tin hợp đồng
* **Contract Address:** `0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D`
* **RPC Sepolia:** `https://ethereum-sepolia-rpc.publicnode.com`

#### 2. Phân tích mã nguồn contract
Hợp đồng đã verified trên Sepolia Etherscan:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract x0 {
    MockToken x1;
    bytes32 private x2;   // slot 1
    bytes32 private x3;   // slot 2
    bytes   private x4;   // slot 3 (cipherFlag)
    address private x6;

    constructor(address _x6) {
        x2 = 0x7ccb3a440e383635148b237df8bb22dff0b594425beae88d6e1623df0bc7669b;
        x3 = 0x7ccb3a440e383635148b237d13473c069ba9ffd6545c58ee37e969b87d181c01;
        x6 = _x6;
    }

    function x7() public view returns (address) {
        return address(uint160(uint256(x2) ^ uint256(x3))); // hidden owner
    }

    function x9(address who) public view returns (string memory) {
        require(who == x7(), "only hidden owner");
        return _decrypt(x4, who);
    }
}
```

* Function selectors:
  * `0x282940a7`: `x7()`  Lấy `hiddenOwner`
  * `0xf8e6e11f`: `x9(address)`  Trả về flag nếu `who == hiddenOwner`

#### 3. Tính toán Hidden Owner
```python
slot1 = 0x7ccb3a440e383635148b237df8bb22dff0b594425beae88d6e1623df0bc7669b
slot2 = 0x7ccb3a440e383635148b237d13473c069ba9ffd6545c58ee37e969b87d181c01
hidden_owner = hex(slot1 ^ slot2)
# hidden_owner = 0xebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a
```

#### 4. Khai thác qua RPC để lấy Flag
Chuẩn bị Calldata cho `x9(address)`:
* Selector: `0xf8e6e11f`
* Address pad 32 bytes: `000000000000000000000000ebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a`

  <img width="975" height="261" alt="image" src="https://github.com/user-attachments/assets/4c809083-df4d-4f7b-bcb2-33a04bc13702" />


Script curl & giải mã:
```bash
curl -s -X POST [https://ethereum-sepolia-rpc.publicnode.com](https://ethereum-sepolia-rpc.publicnode.com) \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D","data":"0xf8e6e11f000000000000000000000000ebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a"},"latest"],"id":1}' \
  | grep -o '"result":"0x[^"]*"' | cut -d'"' -f4 \
  | python3 -c "
import sys
h = sys.stdin.read().strip()[2:]
b = bytes.fromhex(h)
offset = int.from_bytes(b, 'big')
length = int.from_bytes(b[offset:offset+32], 'big')
flag = b[offset+32:offset+32+length].decode('utf-8', errors='ignore')
print('FLAG:', flag)
"
```

* **Output:**
```text
FLAG: 51.5049,0.0348
```
