# PairTriage Router 数据

本目录由 `care_vul/scripts/build_router_data.py` 生成。源 PrimeVul 文件保持只读。

## 协议

- `official/`：保留官方划分和行顺序。异常配对保留但禁止计算 pair-consistency loss。
- `code_clean/`：以函数对为原子，从 train/valid 移除配对异常、未映射标签和跨划分词法近重复；test保持不变并携带风险标记。

## Router目标

Router预测10个候选漏洞机制：`memory`、`injection`、`input`、`numeric`、`resource`、`concurrency`、`access`、`crypto`、`information`、`logic`。

`benign`不是Router family。漏洞版和修复版共享机制标签，最终漏洞/安全判断由下游验证器完成。

## 输入边界

模型只能读取 `vulnerable.func` 或 `fixed.func`。CWE、CVE、项目、提交、文件哈希和二分类标签不能拼入模型输入。

## 复现

```powershell
python care_vul/scripts/build_router_data.py `
  --data-dir care_vul/third_party/VulTriage/data/PRIMEVUL `
  --mapping config/cwe_coarse_mapping.json `
  --audit-dir pair_triage_data_audit `
  --output-dir care_vul/data/router
```
