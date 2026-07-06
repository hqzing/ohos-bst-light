# ohos-bst-light

`binary-sign-tool` 轻量重写版 —— 基于 `binary-sign-tool` 开源代码逆向分析出二进制自签名算法后，用 C 语言和 Python 各重写一份签名工具实现，不依赖官方源码、不依赖 openssl / cJSON / elfio。

## 用法

```sh
# C 语言版
gcc self-sign.c -o self-sign           # 需先构建后使用，支持 gcc 和 clang
./self-sign <input_file>               # 对原始文件进行签名
./self-sign <input_file> <output_file> # 签名后保存到新文件

# Python 版
python3 self-sign.py <input_file>
python3 self-sign.py <input_file> <output_file>
```

## 文件

| 文件 | 用途 |
|------|------|
| `self-sign.c` | C 语言实现，自带 SHA-256 + ELF64 section 注入器，零第三方依赖 |
| `self-sign.py` | Python 实现，仅用标准库 hashlib，零第三方依赖 |

## 相关项目 
- [ohos-bst-portable](https://github.com/hqzing/ohos-bst-portable): 剥离官方源码独立编出 `binary-sign-tool`，产物与 OpenHarmony SDK 里集成的 `binary-sign-tool` 同源同质。此项目可以让开发者排除无关组件干扰、专注研究 `binary-sign-tool` 的代码逻辑。
