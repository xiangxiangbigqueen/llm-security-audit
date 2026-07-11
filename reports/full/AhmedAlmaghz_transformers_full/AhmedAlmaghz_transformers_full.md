# CodeSentinel 安全审计报告

## 项目信息
- **项目名称:** transformers
- **编程语言:** {"Python": 99.4, "C": 0.4, "C++": 0.2}
- **文件数量:** 0
- **审计时间:** 2026-07-11 07:34:29

## 执行摘要

CodeSentinel 安全审计报告 - transformers

**风险评分:** 100/100

## 漏洞统计

| 严重等级 | 数量 |
|---------|------|
| Critical | 70 |
| High | 335 |
| Medium | 179 |
| Low | 13 |
| **总计** | **597** |

## 漏洞详情

### VULN-4CC3F322 - 路径遍历

- **严重等级:** HIGH
- **文件位置:** `benchmark\optimum_benchmark_wrapper.py:6`
- **数据流:** 用户通过 --config-dir 参数传入 config_dir，该值直接作为 --config-dir 选项的值传递给子进程，未进行路径规范化或验证。
- **判断理由:** config_dir 参数可能包含 '../' 等路径遍历序列，导致程序访问非预期的目录，读取或写入敏感文件。虽然 subprocess.run 本身不直接操作文件，但 optimum-benchmark 工具可能根据 config_dir 读取配置文件，攻击者可以指定任意路径，导致信息泄露或配置篡改。

**代码片段:**
```
subprocess.run(["optimum-benchmark", "--config-dir", f"{config_dir}", "--config-name", f"{config_name}"] + ...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-D749493F - 命令注入

- **严重等级:** CRITICAL
- **文件位置:** `examples\run_on_remote.py:56`
- **数据流:** 用户通过命令行参数 --example 和未知参数传入数据，这些数据被直接拼接到 f-string 中，然后传递给 cluster.run() 执行远程命令。
- **判断理由:** args.example 和 unknown 参数来自用户输入，虽然 unknown 参数使用了 shlex.quote() 进行转义，但 args.example 直接通过 f-string 拼接进命令字符串，未经过任何转义或验证。攻击者可以通过 --example 参数注入任意命令，例如传入 '; malicious_command' 来执行恶意操作。

**代码片段:**
```
cluster.run([f'python transformers/examples/{args.example} {" ".join(shlex.quote(arg) for arg in unknown)}'])
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-7A6D8C22 - 路径遍历

- **严重等级:** MEDIUM
- **文件位置:** `examples\run_on_remote.py:53`
- **数据流:** 用户通过 --example 参数控制 example_dir，该值被用于构建文件路径，可能读取任意位置的 requirements.txt 文件。
- **判断理由:** example_dir 来自用户输入，未进行路径规范化或白名单校验。攻击者可以通过路径遍历（如 '../../etc/passwd'）读取远程服务器上的任意文件，虽然命令是 pip install -r，但路径遍历仍可能导致意外文件被读取或执行。

**代码片段:**
```
cluster.run([f"pip install -r transformers/examples/{example_dir}/requirements.txt"])
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-D72C7A17 - 路径遍历

- **严重等级:** MEDIUM
- **文件位置:** `examples\run_on_remote.py:56`
- **数据流:** 用户通过 --example 参数控制 args.example，该值被直接用于构建远程执行的文件路径。
- **判断理由:** args.example 未经过路径校验，攻击者可以通过路径遍历（如 '../../tmp/malicious.py'）执行远程服务器上任意位置的 Python 脚本，导致任意代码执行。

**代码片段:**
```
cluster.run([f'python transformers/examples/{args.example} ...'])
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-05A42D66 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/flax/image-captioning/create_model_from_encoder_decoder_models.py:69`
- **数据流:** 用户通过命令行参数 --encoder_config_name 传入模型名称或路径 → 直接传递给 AutoConfig.from_pretrained() 从 Hugging Face Hub 下载 → 未指定 revision 参数
- **判断理由:** from_pretrained() 调用未指定 revision 参数，默认下载最新版本。如果模型仓库被恶意更新，将自动下载包含后门或恶意代码的模型，导致供应链攻击。攻击者可以上传恶意模型版本，所有未固定版本的调用都会受到影响。

**代码片段:**
```
encoder_config = AutoConfig.from_pretrained(model_args.encoder_config_name)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-2F6CA6CD - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/flax/image-captioning/create_model_from_encoder_decoder_models.py:72`
- **数据流:** 用户通过命令行参数 --encoder_model_name_or_path 传入模型名称或路径 → 直接传递给 AutoConfig.from_pretrained() 从 Hugging Face Hub 下载 → 未指定 revision 参数
- **判断理由:** from_pretrained() 调用未指定 revision 参数，默认下载最新版本。如果模型仓库被恶意更新，将自动下载包含后门或恶意代码的模型，导致供应链攻击。

**代码片段:**
```
encoder_config = AutoConfig.from_pretrained(model_args.encoder_model_name_or_path)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-EFDBDAE9 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/flax/image-captioning/create_model_from_encoder_decoder_models.py:76`
- **数据流:** 用户通过命令行参数 --decoder_config_name 传入模型名称或路径 → 直接传递给 AutoConfig.from_pretrained() 从 Hugging Face Hub 下载 → 未指定 revision 参数
- **判断理由:** from_pretrained() 调用未指定 revision 参数，默认下载最新版本。如果模型仓库被恶意更新，将自动下载包含后门或恶意代码的模型，导致供应链攻击。

**代码片段:**
```
decoder_config = AutoConfig.from_pretrained(model_args.decoder_config_name)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-2CF60D6C - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/flax/image-captioning/create_model_from_encoder_decoder_models.py:79`
- **数据流:** 用户通过命令行参数 --decoder_model_name_or_path 传入模型名称或路径 → 直接传递给 AutoConfig.from_pretrained() 从 Hugging Face Hub 下载 → 未指定 revision 参数
- **判断理由:** from_pretrained() 调用未指定 revision 参数，默认下载最新版本。如果模型仓库被恶意更新，将自动下载包含后门或恶意代码的模型，导致供应链攻击。

**代码片段:**
```
decoder_config = AutoConfig.from_pretrained(model_args.decoder_model_name_or_path)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-D771A641 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/flax/image-captioning/create_model_from_encoder_decoder_models.py:105`
- **数据流:** 用户通过命令行参数 --encoder_model_name_or_path 传入模型名称或路径 → 直接传递给 AutoImageProcessor.from_pretrained() 从 Hugging Face Hub 下载 → 未指定 revision 参数
- **判断理由:** from_pretrained() 调用未指定 revision 参数，默认下载最新版本。如果模型仓库被恶意更新，将自动下载包含后门或恶意代码的模型，导致供应链攻击。

**代码片段:**
```
image_processor = AutoImageProcessor.from_pretrained(model_args.encoder_model_name_or_path)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-5E658158 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/flax/image-captioning/create_model_from_encoder_decoder_models.py:107`
- **数据流:** 用户通过命令行参数 --decoder_model_name_or_path 传入模型名称或路径 → 直接传递给 AutoTokenizer.from_pretrained() 从 Hugging Face Hub 下载 → 未指定 revision 参数
- **判断理由:** from_pretrained() 调用未指定 revision 参数，默认下载最新版本。如果模型仓库被恶意更新，将自动下载包含后门或恶意代码的模型，导致供应链攻击。

**代码片段:**
```
tokenizer = AutoTokenizer.from_pretrained(model_args.decoder_model_name_or_path)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-6F1291E7 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/flax/language-modeling/run_bart_dlm_flax.py:544`
- **数据流:** 用户通过命令行参数指定dataset_name和dataset_config_name，这些参数直接传递给load_dataset()函数，没有指定revision参数来固定数据集版本
- **判断理由:** load_dataset()调用没有指定revision参数，这意味着每次运行时可能下载不同版本的数据集。攻击者可能通过更新Hub上的数据集来注入恶意代码或数据，导致供应链攻击。

**代码片段:**
```
load_dataset(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-D9385EB1 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/flax/language-modeling/run_bart_dlm_flax.py:621`
- **数据流:** 用户通过命令行参数指定model_name_or_path，该参数直接传递给from_pretrained()函数，没有指定revision参数来固定模型版本
- **判断理由:** from_pretrained()调用没有指定revision参数，这意味着每次运行时可能下载不同版本的模型。攻击者可能通过更新Hub上的模型来注入恶意代码或权重，导致供应链攻击。

**代码片段:**
```
from_pretrained(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-13147E2C - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/flax/language-modeling/run_clm_flax.py:401`
- **数据流:** 用户通过命令行参数指定dataset_name或dataset_config_name，这些参数直接传递给load_dataset()函数，没有指定固定的revision版本号，导致可能加载恶意修改的数据集版本
- **判断理由:** load_dataset()调用时没有使用revision参数固定数据集版本，攻击者可能通过篡改数据集仓库的默认分支来注入恶意数据，导致模型训练被投毒或执行任意代码

**代码片段:**
```
load_dataset()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-2753C6EE - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/flax/language-modeling/run_clm_flax.py:519`
- **数据流:** 用户通过命令行参数指定model_name_or_path或config_name，这些参数直接传递给from_pretrained()函数，没有指定固定的revision版本号
- **判断理由:** from_pretrained()调用时没有使用revision参数固定模型版本，攻击者可能通过篡改模型仓库的默认分支来注入恶意模型权重或代码，导致模型被投毒或执行任意代码

**代码片段:**
```
from_pretrained()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-F5DF2FBE - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `examples/flax/language-modeling/run_mlm_flax.py:443`
- **数据流:** load_dataset() function called without specifying a revision parameter, allowing potential supply chain attacks where the dataset could be silently updated to a malicious version
- **判断理由:** The load_dataset() call does not pin a specific revision (commit hash, tag, or branch). This means the downloaded dataset could change between runs without notice, potentially introducing malicious data or code. This is a supply chain security vulnerability.

**代码片段:**
```
load_dataset(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-CD34FB9D - 不安全的Hugging Face Hub下载（无版本固定）

- **严重等级:** HIGH
- **文件位置:** `examples/flax/language-modeling/run_t5_mlm_flax.py:567`
- **数据流:** 用户通过命令行参数指定dataset_name和dataset_config_name，这些参数直接传递给load_dataset()函数，未指定revision参数固定版本
- **判断理由:** load_dataset()调用未指定revision参数，可能导致从Hugging Face Hub下载恶意修改的数据集版本。攻击者可能通过供应链攻击替换数据集内容，导致模型训练被投毒或执行恶意代码。

**代码片段:**
```
load_dataset()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-E4F8B6ED - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `examples/flax/text-classification/run_flax_glue.py:394`
- **数据流:** 用户通过命令行参数或配置文件指定数据集名称，load_dataset()从Hugging Face Hub下载数据集时未指定固定版本(revision)，可能下载到被恶意篡改的数据集版本
- **判断理由:** bandit静态分析工具检测到[B615]漏洞，load_dataset()调用未指定revision参数，默认使用'main'分支，该分支可能被恶意更新导致供应链攻击

**代码片段:**
```
load_dataset()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-6F1F5480 - 不安全的PyTorch模型加载

- **严重等级:** HIGH
- **文件位置:** `examples\legacy\question-answering\run_squad.py:421`
- **数据流:** 用户通过args.model_name_or_path参数控制模型路径 -> from_pretrained()内部调用torch.load()加载模型权重 -> 反序列化执行任意代码
- **判断理由:** from_pretrained()方法内部会调用torch.load()加载模型权重文件，如果model_name_or_path指向恶意构造的模型文件，会导致反序列化代码执行漏洞。

**代码片段:**
```
model = AutoModelForQuestionAnswering.from_pretrained(args.model_name_or_path, ...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-122F1751 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/legacy/seq2seq/run_eval.py:52`
- **数据流:** 用户通过命令行参数model_name传入模型名称 -> 直接传递给from_pretrained()方法 -> 从Hugging Face Hub下载模型权重
- **判断理由:** from_pretrained()调用未指定revision参数，允许从Hugging Face Hub下载任意版本的模型。攻击者可能上传恶意模型到同名仓库，或利用默认分支的恶意更新。这可能导致任意代码执行，因为模型权重可以包含恶意代码（如PyTorch的pickle反序列化漏洞）。

**代码片段:**
```
model = AutoModelForSeq2SeqLM.from_pretrained(model_name).to(device)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-8DA1CE3B - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/legacy/seq2seq/run_eval.py:56`
- **数据流:** 用户通过命令行参数model_name传入模型名称 -> 直接传递给from_pretrained()方法 -> 从Hugging Face Hub下载tokenizer配置
- **判断理由:** 与第52行相同的问题，tokenizer的from_pretrained()调用也未指定revision参数。tokenizer文件同样可能包含恶意配置，导致代码执行或信息泄露。

**代码片段:**
```
tokenizer = AutoTokenizer.from_pretrained(model_name)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-227F9C3A - 代码注入

- **严重等级:** CRITICAL
- **文件位置:** `examples\legacy\seq2seq\xla_spawn.py:66`
- **数据流:** 用户通过命令行参数 --training_script 传入脚本路径 -> 解析为 Path 对象 -> 提取 stem 作为模块名 -> 传递给 importlib.import_module() 动态导入
- **判断理由:** 攻击者可以指定任意 Python 脚本路径作为 training_script 参数，该路径会被动态导入并执行。由于 importlib.import_module() 会执行模块中的顶级代码，攻击者可以构造恶意脚本实现任意代码执行。虽然 sys.path 被修改为脚本所在目录，但攻击者仍可通过控制脚本内容实现代码注入。

**代码片段:**
```
mod = importlib.import_module(mod_name)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B2EC726B - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\legacy\token-classification\run_ner.py:171`
- **数据流:** 用户通过命令行参数或JSON文件提供model_args.config_name或model_args.model_name_or_path，这些参数直接传递给AutoConfig.from_pretrained()，没有指定revision参数来固定模型版本。
- **判断理由:** from_pretrained()方法在没有指定revision参数时，会从Hugging Face Hub下载最新版本的模型。攻击者如果能够控制或污染模型仓库，可以推送恶意更新，导致用户下载并加载恶意模型。这可能导致代码执行、数据泄露等严重后果。

**代码片段:**
```
config = AutoConfig.from_pretrained(
    model_args.config_name if model_args.config_name else model_args.model_name_or_path,
    num_labels=num_labels,
    id2label=label_map,
    label2id={label: i for i, label in enumerate(labels)},
    cache_dir=model_args.cache_dir,
)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-0C366EA2 - 命令注入

- **严重等级:** CRITICAL
- **文件位置:** `examples\legacy\token-classification\scripts\preprocess.py:5`
- **数据流:** 用户通过命令行参数sys.argv[1]传入dataset路径，该路径在第14行直接用于open()函数打开文件，未进行任何路径验证或过滤。攻击者可以传入恶意路径（如/etc/passwd）或特殊字符导致路径遍历或文件读取。
- **判断理由:** sys.argv直接获取用户输入，未经过滤或验证，直接作为文件路径传递给open()函数，存在路径遍历和任意文件读取风险。攻击者可以通过构造特殊路径读取系统敏感文件。

**代码片段:**
```
dataset = sys.argv[1]
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-8B49CAA8 - 路径遍历

- **严重等级:** HIGH
- **文件位置:** `examples\legacy\token-classification\scripts\preprocess.py:14`
- **数据流:** 用户输入sys.argv[1] -> dataset变量 -> open(dataset, "rt")，未对路径进行任何规范化或白名单校验，攻击者可以使用../等路径穿越符号读取任意文件。
- **判断理由:** open()函数直接使用用户控制的路径参数，未进行路径合法性检查，攻击者可以构造如'../../../etc/passwd'的路径实现目录遍历攻击。

**代码片段:**
```
with open(dataset, "rt") as f_p:
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-6E30227E - 代码注入

- **严重等级:** CRITICAL
- **文件位置:** `examples\pytorch\xla_spawn.py:60`
- **数据流:** 用户通过命令行参数 --training_script 传入脚本路径 -> 解析为 mod_name -> 传递给 importlib.import_module() 动态导入模块
- **判断理由:** 攻击者可以指定任意Python模块路径，importlib.import_module()会动态加载并执行该模块中的代码。由于没有对用户输入的training_script参数进行任何校验或白名单限制，攻击者可以导入恶意模块，导致任意代码执行。

**代码片段:**
```
mod = importlib.import_module(mod_name)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-2E5C9474 - 路径遍历

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\xla_spawn.py:59`
- **数据流:** 用户通过 training_script 参数传入路径 -> 解析为父目录 -> 添加到 sys.path
- **判断理由:** 攻击者可以指定任意路径作为 training_script 参数，该路径的父目录会被添加到 sys.path 中。如果攻击者指定一个包含恶意模块的目录，后续的 import_module 会优先加载该目录中的模块，导致任意代码执行。

**代码片段:**
```
sys.path.append(str(script_fpath.parent.resolve()))
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-2F22527B - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/pytorch/audio-classification/run_audio_classification.py:259`
- **数据流:** 用户通过命令行参数或配置文件传入dataset_name，该参数直接传递给load_dataset()函数，未指定revision参数来固定数据集版本
- **判断理由:** load_dataset()调用时未指定revision参数，默认使用最新版本。攻击者可能通过篡改Hugging Face Hub上的数据集版本（如更新恶意代码到最新分支）来实施供应链攻击。用户无法确保加载的数据集版本是经过验证的，存在代码执行和数据投毒风险。

**代码片段:**
```
load_dataset()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-3B2456DA - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/pytorch/audio-classification/run_audio_classification.py:266`
- **数据流:** 用户通过命令行参数或配置文件传入dataset_name，该参数直接传递给load_dataset()函数，未指定revision参数来固定数据集版本
- **判断理由:** 与第259行相同的漏洞，另一个load_dataset()调用同样未指定revision参数。攻击者可能通过篡改Hugging Face Hub上的数据集版本（如更新恶意代码到最新分支）来实施供应链攻击。用户无法确保加载的数据集版本是经过验证的，存在代码执行和数据投毒风险。

**代码片段:**
```
load_dataset()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-6F8CE2DC - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `examples/pytorch/contrastive-image-text/run_clip.py:301`
- **数据流:** 用户通过命令行参数指定dataset_name，该参数直接传递给load_dataset()函数，未指定revision参数，导致从Hugging Face Hub下载的数据集版本不可控
- **判断理由:** load_dataset()调用未指定revision参数，默认使用最新版本。攻击者可能通过篡改Hub上的数据集版本引入恶意数据，导致模型训练被投毒或执行恶意代码。

**代码片段:**
```
load_dataset()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B3B144EC - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\image-classification\run_image_classification_no_trainer.py:286`
- **数据流:** 用户通过命令行参数 --dataset_name 提供数据集名称，该参数直接传递给 load_dataset() 函数，未指定 revision 参数来固定版本。攻击者可以上传恶意版本的数据集到同一名称下，导致下载恶意代码执行。
- **判断理由:** load_dataset() 调用未指定 revision 参数，默认会下载最新版本。如果攻击者控制了该数据集仓库并上传了恶意代码，用户将下载并执行恶意代码。结合 trust_remote_code=True 时风险更高。

**代码片段:**
```
raw_datasets = load_dataset(
    args.dataset_name,
    trust_remote_code=args.trust_remote_code,
)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-DA85EE90 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\image-classification\run_image_classification_no_trainer.py:293`
- **数据流:** 用户通过命令行参数 --dataset_name 提供数据集名称，该参数直接传递给 load_dataset() 函数，未指定 revision 参数来固定版本。攻击者可以上传恶意版本的数据集到同一名称下，导致下载恶意代码执行。
- **判断理由:** load_dataset() 调用未指定 revision 参数，默认会下载最新版本。如果攻击者控制了该数据集仓库并上传了恶意代码，用户将下载并执行恶意代码。结合 trust_remote_code=True 时风险更高。

**代码片段:**
```
raw_datasets = load_dataset(
    args.dataset_name,
    trust_remote_code=args.trust_remote_code,
)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-1B4F9C1C - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\image-classification\run_image_classification_no_trainer.py:331`
- **数据流:** 用户通过命令行参数 --model_name_or_path 提供模型名称或路径，该参数直接传递给 from_pretrained() 函数，未指定 revision 参数来固定版本。攻击者可以上传恶意版本的模型到同一名称下，导致下载恶意代码执行。
- **判断理由:** from_pretrained() 调用未指定 revision 参数，默认会下载最新版本。如果攻击者控制了该模型仓库并上传了恶意代码，用户将下载并执行恶意代码。结合 trust_remote_code=True 时风险更高。

**代码片段:**
```
config = AutoConfig.from_pretrained(
    args.model_name_or_path,
    trust_remote_code=args.trust_remote_code,
)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-380DA229 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\image-classification\run_image_classification_no_trainer.py:339`
- **数据流:** 用户通过命令行参数 --model_name_or_path 提供模型名称或路径，该参数直接传递给 from_pretrained() 函数，未指定 revision 参数来固定版本。攻击者可以上传恶意版本的模型到同一名称下，导致下载恶意代码执行。
- **判断理由:** from_pretrained() 调用未指定 revision 参数，默认会下载最新版本。如果攻击者控制了该模型仓库并上传了恶意代码，用户将下载并执行恶意代码。结合 trust_remote_code=True 时风险更高。

**代码片段:**
```
image_processor = AutoImageProcessor.from_pretrained(
    args.model_name_or_path,
    trust_remote_code=args.trust_remote_code,
)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-D9861E5F - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\image-classification\run_image_classification_no_trainer.py:343`
- **数据流:** 用户通过命令行参数 --model_name_or_path 提供模型名称或路径，该参数直接传递给 from_pretrained() 函数，未指定 revision 参数来固定版本。攻击者可以上传恶意版本的模型到同一名称下，导致下载恶意代码执行。
- **判断理由:** from_pretrained() 调用未指定 revision 参数，默认会下载最新版本。如果攻击者控制了该模型仓库并上传了恶意代码，用户将下载并执行恶意代码。结合 trust_remote_code=True 时风险更高。

**代码片段:**
```
model = AutoModelForImageClassification.from_pretrained(
    args.model_name_or_path,
    trust_remote_code=args.trust_remote_code,
)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-CD152529 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `examples\pytorch\image-pretraining\run_mae.py:232`
- **数据流:** 用户通过命令行参数或配置文件指定dataset_name，该参数直接传递给load_dataset()函数，未指定revision参数固定版本
- **判断理由:** load_dataset()调用未指定revision参数，默认使用'main'分支。攻击者可能通过篡改Hub仓库内容或进行供应链攻击，在未固定版本的情况下下载恶意数据集，可能导致代码执行或数据投毒。

**代码片段:**
```
load_dataset(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-5A7ACC09 - 不安全的Hugging Face Hub下载（无版本锁定）

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\image-pretraining\run_mim_no_trainer.py:437`
- **数据流:** 用户通过命令行参数--dataset_name指定数据集名称，该参数直接传递给load_dataset()函数，未指定revision参数进行版本锁定。攻击者可以上传恶意版本的数据集到同名仓库，导致供应链攻击。
- **判断理由:** load_dataset()调用未指定revision参数，默认使用最新版本。如果攻击者控制了该数据集仓库，可以上传恶意版本，导致用户下载并执行恶意代码。

**代码片段:**
```
raw_datasets = load_dataset(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-210BC073 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\instance-segmentation\run_instance_segmentation.py:378`
- **数据流:** 用户通过命令行参数dataset_name指定数据集名称，该参数直接传递给load_dataset()函数，未指定revision参数固定版本
- **判断理由:** load_dataset()未指定revision参数，会从Hugging Face Hub下载最新版本的数据集。攻击者可能通过更新Hub上的数据集来注入恶意代码或数据，导致供应链攻击。用户可以通过--dataset_name参数控制下载的数据集，增加了攻击面。

**代码片段:**
```
load_dataset()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-F07F0FD7 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\instance-segmentation\run_instance_segmentation.py:395`
- **数据流:** 用户通过命令行参数model_name_or_path指定模型名称或路径，该参数直接传递给from_pretrained()方法，未指定revision参数固定版本
- **判断理由:** from_pretrained()未指定revision参数，会从Hugging Face Hub下载最新版本的模型。攻击者可能通过更新Hub上的模型权重或配置文件来注入恶意代码，导致供应链攻击。用户可以通过--model_name_or_path参数控制下载的模型，增加了攻击面。

**代码片段:**
```
from_pretrained()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-CF3E5621 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\instance-segmentation\run_instance_segmentation.py:403`
- **数据流:** 用户通过命令行参数model_name_or_path指定模型名称或路径，该参数直接传递给from_pretrained()方法，未指定revision参数固定版本
- **判断理由:** from_pretrained()未指定revision参数，会从Hugging Face Hub下载最新版本的模型。攻击者可能通过更新Hub上的模型权重或配置文件来注入恶意代码，导致供应链攻击。用户可以通过--model_name_or_path参数控制下载的模型，增加了攻击面。

**代码片段:**
```
from_pretrained()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B3A08B48 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\instance-segmentation\run_instance_segmentation_no_trainer.py:463`
- **数据流:** 用户通过命令行参数 --model_name_or_path 传入模型名称 -> 直接传递给 from_pretrained() 函数 -> 从 Hugging Face Hub 下载模型权重和配置
- **判断理由:** AutoModelForUniversalSegmentation.from_pretrained() 调用未指定 revision 参数，默认使用主分支的最新版本。攻击者可能通过篡改 Hub 仓库的主分支来注入恶意模型权重或代码，导致供应链攻击。模型加载可能执行任意代码。

**代码片段:**
```
model = AutoModelForUniversalSegmentation.from_pretrained(args.model_name_or_path, cache_dir=args.cache_dir)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-263C7511 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/pytorch/language-modeling/run_clm.py:318`
- **数据流:** 用户通过命令行参数指定dataset_name和dataset_config_name，直接传递给load_dataset()函数，未指定固定的revision版本
- **判断理由:** 与第309行类似，load_dataset()调用未指定revision参数，存在供应链攻击风险。攻击者可以修改数据集仓库的默认分支内容。

**代码片段:**
```
load_dataset(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-2A5D56D8 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/pytorch/language-modeling/run_clm.py:327`
- **数据流:** 用户通过命令行参数指定dataset_name，直接传递给load_dataset()函数，未指定固定的revision版本
- **判断理由:** 与第309行类似，load_dataset()调用未指定revision参数，存在供应链攻击风险。攻击者可以修改数据集仓库的默认分支内容。

**代码片段:**
```
load_dataset(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-0B51DBE4 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\language-modeling\run_clm_no_trainer.py:329`
- **数据流:** 用户通过命令行参数 --dataset_name 指定数据集名称，该参数直接传递给 load_dataset() 函数，未指定 revision 参数，导致从 Hugging Face Hub 下载时可能获取到恶意版本的数据集
- **判断理由:** load_dataset() 调用未指定 revision 参数，攻击者可能通过篡改 Hub 上的数据集版本（如更新恶意代码到最新版本）来实施供应链攻击。当 trust_remote_code=True 时，恶意数据集代码会在本地执行，造成代码注入风险。

**代码片段:**
```
load_dataset()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-00D35BF6 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\language-modeling\run_clm_no_trainer.py:381`
- **数据流:** 用户通过命令行参数 --model_name_or_path 指定模型路径，该参数直接传递给 AutoModelForCausalLM.from_pretrained() 函数，未指定 revision 参数
- **判断理由:** from_pretrained() 调用未指定 revision 参数，攻击者可能通过篡改 Hub 上的模型版本（如更新恶意权重或代码到最新版本）来实施供应链攻击。当 trust_remote_code=True 时，恶意模型代码会在本地执行，造成代码注入风险。

**代码片段:**
```
from_pretrained()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-9F9CD8FC - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\language-modeling\run_fim_no_trainer.py:397`
- **数据流:** 用户通过命令行参数 --dataset_name 指定数据集名称，该名称直接传递给 load_dataset() 函数，未指定 revision 参数固定版本
- **判断理由:** load_dataset() 未指定 revision 参数，导致从 Hugging Face Hub 下载的数据集可能被恶意更新，存在供应链攻击风险。攻击者可以上传恶意版本的数据集，导致代码执行或数据泄露。

**代码片段:**
```
load_dataset(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-DA44AAE9 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\language-modeling\run_fim_no_trainer.py:401`
- **数据流:** 用户通过命令行参数 --dataset_name 指定数据集名称，该名称直接传递给 load_dataset() 函数，未指定 revision 参数固定版本
- **判断理由:** load_dataset() 未指定 revision 参数，导致从 Hugging Face Hub 下载的数据集可能被恶意更新，存在供应链攻击风险。攻击者可以上传恶意版本的数据集，导致代码执行或数据泄露。

**代码片段:**
```
load_dataset(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-BCD1B504 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\language-modeling\run_fim_no_trainer.py:407`
- **数据流:** 用户通过命令行参数 --dataset_name 指定数据集名称，该名称直接传递给 load_dataset() 函数，未指定 revision 参数固定版本
- **判断理由:** load_dataset() 未指定 revision 参数，导致从 Hugging Face Hub 下载的数据集可能被恶意更新，存在供应链攻击风险。攻击者可以上传恶意版本的数据集，导致代码执行或数据泄露。

**代码片段:**
```
load_dataset(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-2951C06C - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\language-modeling\run_fim_no_trainer.py:424`
- **数据流:** 用户通过命令行参数 --dataset_name 指定数据集名称，该名称直接传递给 load_dataset() 函数，未指定 revision 参数固定版本
- **判断理由:** load_dataset() 未指定 revision 参数，导致从 Hugging Face Hub 下载的数据集可能被恶意更新，存在供应链攻击风险。攻击者可以上传恶意版本的数据集，导致代码执行或数据泄露。

**代码片段:**
```
load_dataset(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-C363332B - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\language-modeling\run_fim_no_trainer.py:427`
- **数据流:** 用户通过命令行参数 --dataset_name 指定数据集名称，该名称直接传递给 load_dataset() 函数，未指定 revision 参数固定版本
- **判断理由:** load_dataset() 未指定 revision 参数，导致从 Hugging Face Hub 下载的数据集可能被恶意更新，存在供应链攻击风险。攻击者可以上传恶意版本的数据集，导致代码执行或数据泄露。

**代码片段:**
```
load_dataset(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-992B4137 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\language-modeling\run_fim_no_trainer.py:448`
- **数据流:** 用户通过命令行参数 --model_name_or_path 指定模型名称或路径，该名称直接传递给 from_pretrained() 函数，未指定 revision 参数固定版本
- **判断理由:** from_pretrained() 未指定 revision 参数，导致从 Hugging Face Hub 下载的模型可能被恶意更新，存在供应链攻击风险。攻击者可以上传恶意版本的模型，导致代码执行或数据泄露。

**代码片段:**
```
from_pretrained(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-415E6C31 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\language-modeling\run_fim_no_trainer.py:453`
- **数据流:** 用户通过命令行参数 --model_name_or_path 指定模型名称或路径，该名称直接传递给 from_pretrained() 函数，未指定 revision 参数固定版本
- **判断理由:** from_pretrained() 未指定 revision 参数，导致从 Hugging Face Hub 下载的模型可能被恶意更新，存在供应链攻击风险。攻击者可以上传恶意版本的模型，导致代码执行或数据泄露。

**代码片段:**
```
from_pretrained(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-331DD1C1 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\language-modeling\run_fim_no_trainer.py:466`
- **数据流:** 用户通过命令行参数 --model_name_or_path 指定模型名称或路径，该名称直接传递给 from_pretrained() 函数，未指定 revision 参数固定版本
- **判断理由:** from_pretrained() 未指定 revision 参数，导致从 Hugging Face Hub 下载的模型可能被恶意更新，存在供应链攻击风险。攻击者可以上传恶意版本的模型，导致代码执行或数据泄露。

**代码片段:**
```
from_pretrained(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-9864F420 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\language-modeling\run_fim_no_trainer.py:476`
- **数据流:** 用户通过命令行参数 --model_name_or_path 指定模型名称或路径，该名称直接传递给 from_pretrained() 函数，未指定 revision 参数固定版本
- **判断理由:** from_pretrained() 未指定 revision 参数，导致从 Hugging Face Hub 下载的模型可能被恶意更新，存在供应链攻击风险。攻击者可以上传恶意版本的模型，导致代码执行或数据泄露。

**代码片段:**
```
from_pretrained(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-701B8F4F - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/pytorch/language-modeling/run_mlm.py:330`
- **数据流:** 用户通过命令行参数指定dataset_name和dataset_config_name，直接传递给load_dataset()函数，未指定revision参数
- **判断理由:** 与第321行类似，此处的load_dataset()调用也未指定revision参数，存在供应链攻击风险。攻击者可上传恶意版本的数据集配置。

**代码片段:**
```
load_dataset(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-58EA3463 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/pytorch/language-modeling/run_mlm.py:339`
- **数据流:** 用户通过命令行参数指定dataset_name，直接传递给load_dataset()函数，未指定revision参数
- **判断理由:** 此处的load_dataset()调用未指定revision参数，存在供应链攻击风险。攻击者可上传恶意版本的数据集。

**代码片段:**
```
load_dataset(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-D629A69F - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\language-modeling\run_plm.py:300`
- **数据流:** 用户通过命令行参数指定dataset_name，该参数直接传递给load_dataset()函数，未指定revision参数进行版本锁定
- **判断理由:** load_dataset()调用未指定revision参数，默认使用'main'分支。攻击者可能通过篡改Hub仓库内容实施供应链攻击，导致下载恶意数据集代码执行

**代码片段:**
```
load_dataset(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-697CA3C1 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\language-modeling\run_plm.py:316`
- **数据流:** 用户通过命令行参数指定dataset_name，该参数直接传递给load_dataset()函数，未指定revision参数进行版本锁定
- **判断理由:** load_dataset()调用未指定revision参数，默认使用'main'分支。攻击者可能通过篡改Hub仓库内容实施供应链攻击，导致下载恶意数据集代码执行

**代码片段:**
```
load_dataset(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-89D6AEC8 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\language-modeling\run_plm.py:334`
- **数据流:** 用户通过命令行参数指定dataset_name，该参数直接传递给load_dataset()函数，未指定revision参数进行版本锁定
- **判断理由:** load_dataset()调用未指定revision参数，默认使用'main'分支。攻击者可能通过篡改Hub仓库内容实施供应链攻击，导致下载恶意数据集代码执行

**代码片段:**
```
load_dataset(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-A9D50C3B - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\language-modeling\run_plm.py:337`
- **数据流:** 用户通过命令行参数指定dataset_name，该参数直接传递给load_dataset()函数，未指定revision参数进行版本锁定
- **判断理由:** load_dataset()调用未指定revision参数，默认使用'main'分支。攻击者可能通过篡改Hub仓库内容实施供应链攻击，导致下载恶意数据集代码执行

**代码片段:**
```
load_dataset(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-D38804EC - Unsafe Hugging Face Hub Download - No Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\object-detection\run_object_detection.py:386`
- **数据流:** load_dataset() is called without specifying a revision parameter, allowing dynamic download of potentially malicious or tampered datasets from Hugging Face Hub
- **判断理由:** Bandit static analysis detected that load_dataset() is called without pinning to a specific revision/commit hash. This means the dataset could be silently updated to include malicious content, leading to potential code execution or data poisoning attacks.

**代码片段:**
```
load_dataset()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-54178829 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `examples\pytorch\object-detection\run_object_detection_no_trainer.py:470`
- **数据流:** from_pretrained() method called without specifying a revision parameter, allowing potential supply chain attacks through malicious model updates
- **判断理由:** Bandit B615: from_pretrained() is called without pinning to a specific revision/commit hash. This applies to AutoModelForObjectDetection.from_pretrained() or similar model loading functions, which could load a compromised model version if the repository is updated maliciously.

**代码片段:**
```
from_pretrained(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-AF3A8849 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `examples\pytorch\object-detection\run_object_detection_no_trainer.py:479`
- **数据流:** from_pretrained() method called without specifying a revision parameter, allowing potential supply chain attacks through malicious model updates
- **判断理由:** Bandit B615: Another from_pretrained() call without revision pinning. This could be for AutoConfig.from_pretrained() or similar, which could load a compromised configuration if the repository is updated maliciously.

**代码片段:**
```
from_pretrained(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-DCE18DBB - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\question-answering\run_qa.py:299`
- **数据流:** 用户通过命令行参数或配置文件指定dataset_name，该参数直接传递给load_dataset()函数，未指定revision参数，导致从Hugging Face Hub下载数据集时可能使用恶意版本。
- **判断理由:** load_dataset()在未指定revision参数时，默认使用最新版本。攻击者可能上传恶意数据集版本，导致代码执行或数据泄露。bandit工具标记为B615漏洞。

**代码片段:**
```
load_dataset()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B69D9613 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\question-answering\run_qa_beam_search_no_trainer.py:368`
- **数据流:** 用户通过命令行参数 --dataset_name 指定数据集名称，该名称直接传递给 load_dataset() 函数，未指定 revision 参数来固定数据集版本。攻击者可以上传恶意版本的数据集到同一名称下，导致用户下载到恶意代码。
- **判断理由:** load_dataset() 调用未指定 revision 参数，默认会下载最新版本的数据集。如果数据集仓库被攻击者控制或篡改，用户可能下载到包含恶意代码的数据集。根据 bandit 规则 B615，这是不安全的 Hugging Face Hub 下载行为。

**代码片段:**
```
load_dataset(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-181C7F2E - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\question-answering\run_seq2seq_qa.py:344`
- **数据流:** 用户通过命令行参数或配置文件指定dataset_name，该参数直接传递给load_dataset()函数，未指定固定的revision版本号，导致从Hugging Face Hub下载的数据集可能被恶意篡改
- **判断理由:** load_dataset()调用时未指定revision参数，默认使用最新版本。攻击者可以上传恶意版本的数据集，导致下载的数据集包含恶意代码或数据，可能造成代码执行或数据泄露。bandit工具标记为B615类型漏洞。

**代码片段:**
```
load_dataset()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-47E064B5 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\question-answering\run_seq2seq_qa.py:362`
- **数据流:** 用户通过命令行参数或配置文件指定dataset_name，该参数直接传递给load_dataset()函数，未指定固定的revision版本号，导致从Hugging Face Hub下载的数据集可能被恶意篡改
- **判断理由:** load_dataset()调用时未指定revision参数，默认使用最新版本。攻击者可以上传恶意版本的数据集，导致下载的数据集包含恶意代码或数据，可能造成代码执行或数据泄露。bandit工具标记为B615类型漏洞。

**代码片段:**
```
load_dataset()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-D8278903 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\semantic-segmentation\run_semantic_segmentation.py:236`
- **数据流:** 用户通过命令行参数data_args.dataset_name和data_args.dataset_config_name指定数据集名称和配置，这些参数直接传递给load_dataset()函数，未指定revision参数固定版本。
- **判断理由:** load_dataset()调用未指定revision参数，默认使用最新版本。攻击者可能通过篡改Hugging Face Hub上的数据集仓库内容，在用户不知情的情况下注入恶意代码。由于trust_remote_code参数可能为True，恶意代码可能在本地执行，导致远程代码执行(RCE)风险。

**代码片段:**
```
dataset = load_dataset(data_args.dataset_name, data_args.dataset_config_name, cache_dir=model_args.cache_dir, trust_remote_code=model_args.trust_remote_code)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B271E15A - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\semantic-segmentation\run_semantic_segmentation.py:261`
- **数据流:** 用户通过data_args.dataset_name指定仓库ID，该参数直接传递给hf_hub_download()函数，未指定revision参数固定版本。
- **判断理由:** hf_hub_download()调用未指定revision参数，默认下载最新版本的文件。攻击者可能通过更新仓库中的配置文件来实施供应链攻击，下载恶意配置文件可能导致后续处理中的安全风险。

**代码片段:**
```
hf_hub_download(repo_id=data_args.dataset_name, filename=config_file, repo_type='dataset', cache_dir=model_args.cache_dir)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-9211E1A0 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\semantic-segmentation\run_semantic_segmentation_no_trainer.py:296`
- **数据流:** 用户通过命令行参数 --dataset_name 指定数据集名称，该参数直接传递给 load_dataset() 函数，未指定 revision 参数固定版本。攻击者可以控制数据集仓库的恶意更新，导致下载恶意代码或数据。
- **判断理由:** load_dataset() 调用未指定 revision 参数，默认使用最新版本。如果数据集仓库被攻击者控制或篡改，用户将下载恶意内容。结合 trust_remote_code=True 时风险更高，因为会执行远程代码。

**代码片段:**
```
raw_datasets = load_dataset(
    args.dataset_name,
    cache_dir=args.cache_dir,
    trust_remote_code=args.trust_remote_code,
)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-73FBC3A8 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\semantic-segmentation\run_semantic_segmentation_no_trainer.py:319`
- **数据流:** 用户通过 --dataset_name 参数控制 repo_id，通过数据集配置文件中的 id2label_file 控制 filename，两者均未固定 revision。攻击者可篡改数据集仓库中的文件内容。
- **判断理由:** hf_hub_download() 未指定 revision 参数，下载的文件内容可能被攻击者恶意修改，导致加载错误的标签映射或执行恶意代码。

**代码片段:**
```
hf_hub_download(
    repo_id=args.dataset_name,
    filename=dataset_config["id2label_file"],
    repo_type="dataset",
    cache_dir=args.cache_dir,
)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-C5184AB4 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\semantic-segmentation\run_semantic_segmentation_no_trainer.py:324`
- **数据流:** 用户通过 --model_name_or_path 参数指定模型路径，直接传递给 from_pretrained()。未固定 revision，攻击者可控制模型仓库内容。
- **判断理由:** AutoConfig.from_pretrained() 未指定 revision 参数，默认下载最新版本。如果模型仓库被篡改，可能加载恶意配置，结合 trust_remote_code=True 可执行任意代码。

**代码片段:**
```
config = AutoConfig.from_pretrained(
    args.model_name_or_path,
    num_labels=num_labels,
    id2label=id2label,
    label2id=label2id,
    cache_dir=args.cache_dir,
    trust_remote_code=args.trust_remote_code,
)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-F49F1768 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\semantic-segmentation\run_semantic_segmentation_no_trainer.py:330`
- **数据流:** 用户通过 --model_name_or_path 参数指定模型路径，直接传递给 from_pretrained()。未固定 revision，攻击者可控制模型仓库内容。
- **判断理由:** AutoModelForSemanticSegmentation.from_pretrained() 未指定 revision 参数，默认下载最新版本。如果模型仓库被篡改，可能加载恶意模型权重或执行恶意代码，结合 trust_remote_code=True 风险极高。

**代码片段:**
```
model = AutoModelForSemanticSegmentation.from_pretrained(
    args.model_name_or_path,
    config=config,
    cache_dir=args.cache_dir,
    trust_remote_code=args.trust_remote_code,
)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-1111DDE8 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/pytorch/speech-pretraining/run_wav2vec2_pretraining_no_trainer.py:453`
- **数据流:** 用户通过命令行参数 --dataset_name 指定数据集名称，该参数直接传递给 load_dataset() 函数，未指定 revision 参数来固定数据集版本。攻击者可以上传恶意版本的数据集到同一名称下，导致供应链攻击。
- **判断理由:** load_dataset() 调用未指定 revision 参数，会默认下载最新版本的数据集。如果数据集仓库被恶意更新，用户将自动获取恶意版本，可能导致代码执行或数据泄露。

**代码片段:**
```
load_dataset()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-9F81360F - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/pytorch/speech-pretraining/run_wav2vec2_pretraining_no_trainer.py:486`
- **数据流:** 用户通过命令行参数 --model_name_or_path 指定模型名称或路径，该参数直接传递给 from_pretrained() 方法，未指定 revision 参数来固定模型版本。攻击者可以上传恶意版本的模型到同一名称下，导致供应链攻击。
- **判断理由:** from_pretrained() 调用未指定 revision 参数，会默认下载最新版本的模型。如果模型仓库被恶意更新，用户将自动获取恶意版本，可能导致代码执行或数据泄露。

**代码片段:**
```
from_pretrained()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-46E9FB2B - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/pytorch/speech-pretraining/run_wav2vec2_pretraining_no_trainer.py:546`
- **数据流:** 用户通过命令行参数 --model_name_or_path 指定模型名称或路径，该参数直接传递给 from_pretrained() 方法，未指定 revision 参数来固定模型版本。攻击者可以上传恶意版本的模型到同一名称下，导致供应链攻击。
- **判断理由:** from_pretrained() 调用未指定 revision 参数，会默认下载最新版本的模型。如果模型仓库被恶意更新，用户将自动获取恶意版本，可能导致代码执行或数据泄露。

**代码片段:**
```
from_pretrained()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-4F4A992D - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `examples/pytorch/speech-recognition/run_speech_recognition_ctc.py:478`
- **数据流:** 用户通过命令行参数指定dataset_name，该参数直接传递给load_dataset()函数，未指定revision参数
- **判断理由:** 与第452行相同，load_dataset()调用未指定revision参数，存在供应链攻击风险

**代码片段:**
```
load_dataset()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-EE26A86D - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `examples/pytorch/speech-recognition/run_speech_recognition_ctc.py:614`
- **数据流:** 用户通过命令行参数指定model_name_or_path，该参数直接传递给from_pretrained()方法，未指定revision参数
- **判断理由:** from_pretrained()调用未指定revision参数，存在供应链攻击风险

**代码片段:**
```
from_pretrained()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-07F26E26 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `examples/pytorch/speech-recognition/run_speech_recognition_ctc_adapter.py:432`
- **数据流:** load_dataset() function called without specifying a revision parameter, allowing potential supply chain attacks where a malicious actor could update the dataset on the Hub
- **判断理由:** Bandit B615: Loading datasets from Hugging Face Hub without pinning a specific revision (commit hash, tag, or branch) means the downloaded content could change at any time, potentially introducing malicious data or code

**代码片段:**
```
load_dataset()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-C139BC14 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `examples\pytorch\speech-recognition\run_speech_recognition_seq2seq.py:344`
- **数据流:** 用户通过命令行参数dataset_name和dataset_config_name指定数据集名称，直接传递给load_dataset()函数，未指定revision参数固定版本
- **判断理由:** load_dataset()调用未指定revision参数，默认使用最新版本。攻击者可能通过篡改Hub上的数据集版本或利用数据集中的恶意代码进行供应链攻击。trust_remote_code参数允许执行远程代码，增加了风险。

**代码片段:**
```
raw_datasets = load_dataset(
    dataset_name,
    dataset_config_name,
    cache_dir=model_args.cache_dir,
    token=model_args.token,
    trust_remote_code=model_args.trust_remote_code,
)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-8BE255BD - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/pytorch/summarization/run_summarization.py:395`
- **数据流:** 用户通过命令行参数 --dataset_name 指定数据集名称，该参数直接传递给 load_dataset() 函数，未指定 revision 参数来固定数据集版本
- **判断理由:** load_dataset() 调用时未指定 revision 参数，这意味着每次运行时可能下载不同版本的数据集。攻击者如果能够控制 Hugging Face Hub 上的数据集仓库，可以推送恶意代码到最新版本，导致用户下载并执行恶意数据。这属于供应链攻击的一种形式。

**代码片段:**
```
load_dataset()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-11CB4A30 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\pytorch\summarization\run_summarization_no_trainer.py:400`
- **数据流:** 用户通过命令行参数 --dataset_name 指定数据集名称，该参数直接传递给 load_dataset() 函数，未指定 revision 参数，导致从 Hugging Face Hub 下载时可能获取到恶意版本的数据集
- **判断理由:** load_dataset() 未指定 revision 参数，攻击者可能通过篡改 Hub 上的数据集版本或利用已存在的恶意版本，导致下载恶意数据，可能包含后门或恶意代码

**代码片段:**
```
load_dataset(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-A6DE6A1F - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/pytorch/text-classification/run_glue.py:290`
- **数据流:** 用户通过命令行参数或配置文件指定dataset_name和dataset_config_name，这些参数直接传递给load_dataset()函数，没有指定固定的revision版本。攻击者可以修改Hub上的数据集内容，导致下载恶意数据。
- **判断理由:** load_dataset()调用时没有指定revision参数，默认会下载最新版本的数据集。如果数据集维护者更新了数据集或数据集仓库被攻陷，用户可能会下载到被篡改的数据集，其中可能包含恶意代码或数据。根据bandit规则B615，这是不安全的做法。

**代码片段:**
```
load_dataset()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-122C54AC - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/pytorch/text-classification/run_glue_no_trainer.py:328`
- **数据流:** 用户通过--model_name_or_path参数控制tokenizer名称，from_pretrained()从Hugging Face Hub下载tokenizer时未指定revision参数
- **判断理由:** 与第322行类似，tokenizer下载也未指定revision，存在供应链攻击风险

**代码片段:**
```
AutoTokenizer.from_pretrained(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-13D9FDC2 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/pytorch/text-classification/run_xnli.py:240`
- **数据流:** 用户通过命令行参数或默认配置调用load_dataset()函数从Hugging Face Hub下载数据集，但未指定固定的revision版本。攻击者可能通过篡改Hub上的数据集内容实施供应链攻击。
- **判断理由:** load_dataset()函数在未指定revision参数时，默认使用最新版本的数据集。这可能导致下载被恶意篡改的数据集版本，引入后门或恶意代码。bandit工具检测到B615漏洞，表明存在不安全的Hub下载操作。

**代码片段:**
```
load_dataset()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-C1A1725D - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/pytorch/text-classification/run_xnli.py:248`
- **数据流:** 用户通过命令行参数或默认配置调用load_dataset()函数从Hugging Face Hub下载数据集，但未指定固定的revision版本。攻击者可能通过篡改Hub上的数据集内容实施供应链攻击。
- **判断理由:** load_dataset()函数在未指定revision参数时，默认使用最新版本的数据集。这可能导致下载被恶意篡改的数据集版本，引入后门或恶意代码。bandit工具检测到B615漏洞，表明存在不安全的Hub下载操作。

**代码片段:**
```
load_dataset()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-73BE932E - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/pytorch/text-generation/run_generation_contrastive_search.py:90`
- **数据流:** 用户通过命令行参数 --model_name_or_path 传入模型名称或路径，该参数直接传递给 from_pretrained() 方法，未指定 revision 参数固定版本。
- **判断理由:** 与第89行相同的问题，from_pretrained() 方法未指定 revision 参数，存在供应链攻击风险。攻击者可以上传恶意模型权重，导致代码执行或数据泄露。

**代码片段:**
```
model = AutoModelForCausalLM.from_pretrained(args.model_name_or_path)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B6E62542 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/pytorch/token-classification/run_ner_no_trainer.py:430`
- **数据流:** 用户通过命令行参数 --tokenizer_name 或 --model_name_or_path 指定 tokenizer 名称，该参数直接传递给 from_pretrained() 方法，未指定 revision 参数
- **判断理由:** from_pretrained() 调用未指定 revision 参数，存在与第402行相同的风险

**代码片段:**
```
tokenizer = AutoTokenizer.from_pretrained(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-64B1AFE8 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `examples/pytorch/translation/run_translation.py:366`
- **数据流:** 用户通过命令行参数指定dataset_name和dataset_config_name，这些参数直接传递给load_dataset()函数，没有指定固定的revision版本。攻击者可以上传恶意版本的数据集到同一个名称下，导致下载恶意数据。
- **判断理由:** 与第344行相同的问题，load_dataset()调用时没有指定revision参数，存在供应链攻击风险。攻击者可以上传包含恶意代码的数据集版本，当用户下载并加载数据集时，恶意代码可能被执行。

**代码片段:**
```
load_dataset()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-704FF854 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/pytorch/translation/run_translation_no_trainer.py:421`
- **数据流:** 用户通过命令行参数 --tokenizer_name 或 --model_name_or_path 控制分词器来源，直接传递给 from_pretrained()，未指定 revision 参数（第三次出现）
- **判断理由:** 与第401行相同的漏洞，在评估阶段再次加载分词器，同样未指定 revision 参数，存在供应链攻击风险。

**代码片段:**
```
tokenizer = AutoTokenizer.from_pretrained(
    args.tokenizer_name if args.tokenizer_name else args.model_name_or_path,
    use_fast=not args.use_slow_tokenizer,
)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B10F8A45 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\research_projects\bertology\run_prune_gpt.py:353`
- **数据流:** 导入语句 -> 模型加载 -> 可能从Hugging Face Hub下载未指定版本的模型
- **判断理由:** Bandit静态分析工具检测到B615漏洞：使用from_pretrained()从Hugging Face Hub加载模型时没有指定revision参数。这可能导致加载恶意或未经验证的模型版本，存在供应链攻击风险。攻击者可能上传恶意模型权重，导致代码执行或数据泄露。

**代码片段:**
```
from transformers import GPT2LMHeadModel
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-6BF505CA - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `examples\research_projects\codeparrot\examples\train_complexity_predictor.py:60`
- **数据流:** 用户通过命令行参数间接控制模型检查点路径，但此处数据集名称是硬编码的。然而，load_dataset()未指定revision参数，导致从Hugging Face Hub下载的数据集可能被恶意更新或替换，造成供应链攻击风险。
- **判断理由:** load_dataset()函数默认从Hugging Face Hub下载最新版本的数据集，未固定revision（如commit hash或tag）。攻击者可能通过更新Hub上的数据集引入恶意数据，影响模型训练结果或注入后门。

**代码片段:**
```
dataset = load_dataset("codeparrot/codecomplex", split="train")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B3365005 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `examples/research_projects/codeparrot/scripts/codeparrot_training.py:128`
- **数据流:** 用户通过命令行参数args.dataset_name_valid指定验证数据集名称，该参数直接传递给load_dataset()函数，未指定revision参数固定版本。
- **判断理由:** 与第126行相同的问题，验证数据集加载也未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
valid_data = load_dataset(args.dataset_name_valid, split="train", **ds_kwargs)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-BC3D1A75 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\research_projects\codeparrot\scripts\human_eval.py:161`
- **数据流:** 用户通过命令行参数args.model_ckpt指定模型检查点路径，该参数直接传递给from_pretrained方法，未指定revision参数，可能导致下载恶意或未经验证的模型版本。
- **判断理由:** 与第159行类似，模型加载同样未指定revision，存在供应链攻击风险，攻击者可上传恶意模型文件，导致代码执行或数据泄露。

**代码片段:**
```
model = AutoModelForCausalLM.from_pretrained(args.model_ckpt)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-DC7531D4 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\research_projects\codeparrot\scripts\initialize_model.py:11`
- **数据流:** 用户通过命令行参数args.tokenizer_name指定模型名称，该参数直接传递给from_pretrained()方法，未指定revision参数，导致可能下载恶意版本
- **判断理由:** from_pretrained()方法默认从Hugging Face Hub下载模型，如果不指定revision（如commit hash或tag），则始终下载最新版本。攻击者可能上传恶意版本到Hub，导致供应链攻击。用户输入args.tokenizer_name来自命令行参数，可能被恶意控制。

**代码片段:**
```
tokenizer = AutoTokenizer.from_pretrained(args.tokenizer_name)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-4160B0E5 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\research_projects\codeparrot\scripts\initialize_model.py:21`
- **数据流:** 用户通过命令行参数args.config_name指定配置名称，该参数直接传递给from_pretrained()方法，未指定revision参数，导致可能下载恶意版本
- **判断理由:** 与第11行类似，AutoConfig.from_pretrained()同样未指定revision参数，依赖用户输入args.config_name从Hub下载配置。攻击者可利用此漏洞植入恶意配置，导致模型加载时执行恶意代码或产生不可预测行为。

**代码片段:**
```
config = AutoConfig.from_pretrained(args.config_name, **config_kwargs)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-69CF3652 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `examples\research_projects\codeparrot\scripts\validation_loss.py:47`
- **数据流:** 用户通过命令行参数args.dataset_name指定数据集名称，该参数直接传递给load_dataset()函数，未指定revision参数，导致可能加载恶意或未经验证的数据集版本。
- **判断理由:** load_dataset()函数在未指定revision参数时，默认加载最新版本的数据集。攻击者可能上传恶意数据集到Hugging Face Hub，或利用已上传数据集的恶意版本，导致代码执行或数据泄露。

**代码片段:**
```
valid_data = load_dataset(args.dataset_name, split="train", **ds_kwargs)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-BA64D7D5 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `examples\research_projects\codeparrot\scripts\validation_loss.py:87`
- **数据流:** 用户通过命令行参数args.model_ckpt指定模型检查点路径，该参数直接传递给from_pretrained()函数，未指定revision参数，导致可能加载恶意或未经验证的模型版本。
- **判断理由:** from_pretrained()函数在未指定revision参数时，默认加载最新版本的模型。攻击者可能上传恶意模型到Hugging Face Hub，或利用已上传模型的恶意版本，导致代码执行（如通过pickle反序列化）或数据泄露。

**代码片段:**
```
model = AutoModelForCausalLM.from_pretrained(args.model_ckpt)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-188D2978 - 不安全的PyTorch模型加载

- **严重等级:** HIGH
- **文件位置:** `examples/research_projects/distillation/run_squad_w_distillation.py:444`
- **数据流:** 根据bandit报告，第444行存在另一个不安全的torch.load调用
- **判断理由:** bandit静态分析工具检测到第444行存在不安全的PyTorch加载操作，同样存在pickle反序列化漏洞风险。

**代码片段:**
```
未在提供的代码片段中显示，但bandit报告第444行存在[B614]问题
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-04129C5B - 不安全的反序列化 (Pickle)

- **严重等级:** CRITICAL
- **文件位置:** `examples/research_projects/distillation/train.py:264`
- **数据流:** 代码导入了pickle模块，该模块在反序列化不可信数据时存在安全风险。虽然当前代码片段未显示具体使用位置，但bandit工具在264行和269行检测到了pickle的使用。
- **判断理由:** Pickle反序列化可以执行任意代码，当反序列化的数据来自不可信来源时，攻击者可以构造恶意的pickle数据导致远程代码执行。该代码中使用了pickle模块，如果用于加载用户提供的数据文件，将构成严重安全风险。

**代码片段:**
```
import pickle
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-989C1DEA - 不安全的反序列化 (Pickle)

- **严重等级:** CRITICAL
- **文件位置:** `examples/research_projects/distillation/train.py:269`
- **数据流:** 代码导入了pickle模块，该模块在反序列化不可信数据时存在安全风险。虽然当前代码片段未显示具体使用位置，但bandit工具在264行和269行检测到了pickle的使用。
- **判断理由:** Pickle反序列化可以执行任意代码，当反序列化的数据来自不可信来源时，攻击者可以构造恶意的pickle数据导致远程代码执行。该代码中使用了pickle模块，如果用于加载用户提供的数据文件，将构成严重安全风险。

**代码片段:**
```
import pickle
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-46B22BE0 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** MEDIUM
- **文件位置:** `examples/research_projects/distillation/scripts/binarized_data.py:48`
- **数据流:** 用户通过命令行参数 --tokenizer_name 传入模型名称，直接传递给 from_pretrained() 方法，未指定 revision 参数。攻击者可以构造恶意的 tokenizer_name 指向恶意仓库，或利用仓库中未固定版本的更新引入恶意代码。
- **判断理由:** from_pretrained() 方法默认从 Hugging Face Hub 下载模型，如果不指定 revision 参数，将下载最新版本。攻击者可以上传同名恶意模型到 Hub，或利用仓库维护者更新引入后门。用户输入 args.tokenizer_name 直接控制下载目标，存在供应链攻击风险。

**代码片段:**
```
tokenizer = BertTokenizer.from_pretrained(args.tokenizer_name)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-19F494E2 - Path Traversal

- **严重等级:** MEDIUM
- **文件位置:** `examples/research_projects/distillation/scripts/binarized_data.py:72`
- **数据流:** 用户通过命令行参数 --file_path 传入文件路径，直接用于 open() 函数。攻击者可以传入 '../etc/passwd' 等路径遍历字符串读取任意文件。
- **判断理由:** args.file_path 来自用户输入，未进行任何路径校验或规范化。攻击者可以通过路径遍历读取系统敏感文件。虽然当前代码只读取文件内容，但结合其他漏洞可能造成信息泄露。

**代码片段:**
```
with open(args.file_path, "r", encoding="utf8") as fp:
    data = fp.readlines()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-F3E83418 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/research_projects/jax-projects/hybrid_clip/run_hybrid_clip.py:336`
- **数据流:** Bandit静态分析工具在Line 336检测到from_pretrained()调用未指定revision参数，但实际代码中该行仅为import语句。Bandit可能误报或检测到其他位置的from_pretrained调用。
- **判断理由:** Bandit工具报告Line 336存在B615漏洞，但该行仅为import语句。可能Bandit误报，或者实际from_pretrained调用在代码的其他位置（如模型加载部分），但提供的代码片段不完整。如果确实存在未指定revision的from_pretrained调用，则存在供应链攻击风险，攻击者可能上传恶意模型版本。

**代码片段:**
```
from transformers import AutoTokenizer, HfArgumentParser, TrainingArguments, is_tensorboard_available, set_seed
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-41378B4B - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/research_projects/longform-qa/eli5_app.py:33`
- **数据流:** 用户通过from_pretrained()从Hugging Face Hub下载模型，未指定revision参数
- **判断理由:** 与第26行相同的问题，未固定模型版本，存在供应链攻击风险。

**代码片段:**
```
s2s_model = AutoModelForSeq2SeqLM.from_pretrained("yjernite/bart_eli5").to("cuda:0")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-3296EA6F - Unsafe PyTorch load

- **严重等级:** CRITICAL
- **文件位置:** `examples/research_projects/longform-qa/eli5_app.py:34`
- **数据流:** 从本地文件系统加载PyTorch模型文件，未进行任何安全校验
- **判断理由:** torch.load()默认使用pickle反序列化，可以执行任意代码。如果文件被篡改或来自不可信来源，攻击者可以植入恶意代码。应使用torch.load(..., weights_only=True)或验证文件完整性。

**代码片段:**
```
save_dict = torch.load("seq2seq_models/eli5_bart_model_blm_2.pth")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-6988E0C0 - Unsafe PyTorch load

- **严重等级:** CRITICAL
- **文件位置:** `examples/research_projects/longform-qa/eli5_utils.py:388`
- **数据流:** from_file参数直接传递给torch.load()，未进行任何校验或限制
- **判断理由:** torch.load()默认使用pickle反序列化，加载恶意文件可导致任意代码执行。from_file参数来自外部输入，存在严重安全风险

**代码片段:**
```
state_dict = torch.load(from_file)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-D6D58035 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\research_projects\luke\run_luke_ner_no_trainer.py:352`
- **数据流:** 用户通过命令行参数 --model_name_or_path 指定模型名称，该参数直接传递给 from_pretrained() 函数，未指定 revision 参数
- **判断理由:** from_pretrained() 未指定 revision 参数，攻击者可以上传恶意版本的模型到 Hugging Face Hub，当用户加载模型时可能执行恶意代码

**代码片段:**
```
model = LukeForEntitySpanClassification.from_pretrained(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-BCDC193E - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\research_projects\luke\run_luke_ner_no_trainer.py:354`
- **数据流:** 用户通过命令行参数 --model_name_or_path 指定模型名称，该参数直接传递给 from_pretrained() 函数，未指定 revision 参数
- **判断理由:** tokenizer 的 from_pretrained() 调用也未指定 revision 参数，存在供应链攻击风险

**代码片段:**
```
tokenizer = LukeTokenizer.from_pretrained(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-0B08887E - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\research_projects\luke\run_luke_ner_no_trainer.py:374`
- **数据流:** 用户通过命令行参数 --tokenizer_name 指定分词器名称，该参数直接传递给 from_pretrained() 函数，未指定 revision 参数
- **判断理由:** 另一个 tokenizer 的 from_pretrained() 调用未指定 revision 参数，存在供应链攻击风险

**代码片段:**
```
tokenizer = LukeTokenizer.from_pretrained(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-D68A9BD6 - 代码注入

- **严重等级:** CRITICAL
- **文件位置:** `examples\research_projects\lxmert\extracting_data.py:137`
- **数据流:** 用户通过命令行参数 -s/--subset_list 指定文件路径 -> 文件内容被读取 -> 传递给 tryload 函数 -> 在 json.load 失败后尝试 eval(stream.read()) 执行文件内容
- **判断理由:** eval() 函数会执行任意Python代码。攻击者可以构造一个恶意文件作为 subset_list 参数传入，当文件内容不是合法JSON时，程序会尝试 eval() 执行文件内容，导致任意代码执行。这是一个严重的安全漏洞，攻击者可以完全控制服务器。

**代码片段:**
```
data = eval(stream.read())
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-0AFCEDB7 - 不安全的PyTorch模型加载

- **严重等级:** HIGH
- **文件位置:** `examples\research_projects\lxmert\modeling_frcnn.py:1750`
- **数据流:** 从utils模块导入load_checkpoint函数，该函数可能使用torch.load()加载模型权重，而torch.load()默认使用pickle反序列化，可能执行任意代码
- **判断理由:** Bandit静态分析工具在Line 1750检测到[B614]不安全PyTorch加载。PyTorch的torch.load()函数默认使用Python的pickle模块进行反序列化，这可能导致任意代码执行。如果模型权重文件来自不可信来源或被恶意篡改，攻击者可以在权重文件中嵌入恶意代码，在加载时执行。虽然代码中未直接显示torch.load()调用，但导入的load_checkpoint函数很可能内部使用了torch.load()，且未指定weights_only=True参数来限制反序列化内容。

**代码片段:**
```
from utils import WEIGHTS_NAME, Config, cached_path, hf_bucket_url, is_remote_url, load_checkpoint
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-0D282737 - 不安全的文件解压 - tarfile.extractall

- **严重等级:** HIGH
- **文件位置:** `examples/research_projects/lxmert/utils.py:478`
- **数据流:** 使用tarfile.extractall()解压tar文件，未对压缩包内的文件路径进行验证。
- **判断理由:** tarfile.extractall()默认不会检查压缩包内文件的路径，恶意tar文件可能包含路径穿越攻击（如../../etc/passwd），覆盖系统关键文件。

**代码片段:**
```
tarfile.extractall used without any validation (line 478)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-86D22197 - 不安全的eval使用

- **严重等级:** CRITICAL
- **文件位置:** `examples/research_projects/lxmert/utils.py:496`
- **数据流:** 代码中使用了eval()或类似的不安全函数来解析数据。
- **判断理由:** eval()可以执行任意Python代码，如果传入的数据包含恶意代码，将导致远程代码执行。应使用ast.literal_eval()替代。

**代码片段:**
```
Use of possibly insecure function - consider using safer ast.literal_eval (line 496)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-A0C7F301 - 请求未设置超时 - SSRF风险

- **严重等级:** MEDIUM
- **文件位置:** `examples/research_projects/lxmert/utils.py:498`
- **数据流:** 另一处使用requests库发起HTTP请求，未设置timeout参数。
- **判断理由:** 与第271行相同的漏洞，未设置超时可能导致资源耗尽。

**代码片段:**
```
requests without timeout (line 498)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-9F0DFA48 - 不安全的eval使用

- **严重等级:** CRITICAL
- **文件位置:** `examples/research_projects/lxmert/utils.py:505`
- **数据流:** 另一处使用eval()或类似的不安全函数来解析数据。
- **判断理由:** 与第496行相同的漏洞，存在远程代码执行风险。

**代码片段:**
```
Use of possibly insecure function - consider using safer ast.literal_eval (line 505)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-2758C886 - 请求未设置超时 - SSRF风险

- **严重等级:** MEDIUM
- **文件位置:** `examples/research_projects/lxmert/utils.py:513`
- **数据流:** 第三处使用requests库发起HTTP请求，未设置timeout参数。
- **判断理由:** 与第271行相同的漏洞，未设置超时可能导致资源耗尽。

**代码片段:**
```
requests without timeout (line 513)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-7B5AAF9F - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** MEDIUM
- **文件位置:** `examples/research_projects/mlm_wwm/run_mlm_wwm.py:258`
- **数据流:** 用户通过命令行参数或配置文件指定dataset_name，该参数直接传递给load_dataset()函数，未指定revision参数进行版本锁定
- **判断理由:** load_dataset()函数从Hugging Face Hub下载数据集时，未指定revision参数进行版本锁定。攻击者可能通过篡改数据集仓库的默认分支内容，导致用户下载到恶意修改的数据集，可能包含后门或恶意代码。

**代码片段:**
```
load_dataset(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-5263080E - 不安全的反序列化 (Unsafe PyTorch load)

- **严重等级:** CRITICAL
- **文件位置:** `examples\research_projects\movement-pruning\bertarize.py:36`
- **数据流:** 用户通过命令行参数 --model_name_or_path 提供路径，该路径被直接用于 os.path.join 构造文件路径，然后传递给 torch.load() 进行反序列化。攻击者可以控制该路径指向恶意构造的 .bin 文件，从而在反序列化时执行任意代码。
- **判断理由:** torch.load() 默认使用 pickle 模块进行反序列化，而 pickle 在加载数据时可能执行任意 Python 代码。如果攻击者能够控制 model_name_or_path 参数指向一个恶意构造的 pytorch_model.bin 文件（例如通过符号链接或直接提供恶意路径），则可能导致远程代码执行。虽然 model_name_or_path 来自命令行参数，但在某些场景下（如自动化脚本或共享环境）可能被攻击者利用。建议使用 torch.load(..., map_location='cpu', weights_only=True) 或使用安全的序列化格式。

**代码片段:**
```
model = torch.load(os.path.join(model_name_or_path, "pytorch_model.bin"))
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-E7FA75DC - 不安全的PyTorch模型加载

- **严重等级:** HIGH
- **文件位置:** `examples\research_projects\movement-pruning\masked_run_squad.py:165`
- **数据流:** 用户通过args.model_name_or_path指定模型路径，该路径可能指向恶意构造的.pt文件，torch.load()默认使用pickle反序列化，可执行任意代码
- **判断理由:** torch.load()默认使用pickle模块进行反序列化，如果加载的模型文件来自不可信来源，攻击者可以构造恶意pickle数据在反序列化时执行任意代码。args.model_name_or_path由用户控制，存在严重安全风险。

**代码片段:**
```
optimizer.load_state_dict(torch.load(os.path.join(args.model_name_or_path, "optimizer.pt")))
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-683558BD - 不安全的PyTorch模型加载

- **严重等级:** HIGH
- **文件位置:** `examples\research_projects\movement-pruning\masked_run_squad.py:166`
- **数据流:** 用户通过args.model_name_or_path指定模型路径，该路径可能指向恶意构造的.pt文件，torch.load()默认使用pickle反序列化，可执行任意代码
- **判断理由:** 与第165行相同，torch.load()默认使用pickle反序列化，args.model_name_or_path由用户控制，加载恶意文件可导致任意代码执行。

**代码片段:**
```
scheduler.load_state_dict(torch.load(os.path.join(args.model_name_or_path, "scheduler.pt")))
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-C29B4C03 - 不安全的PyTorch模型加载

- **严重等级:** HIGH
- **文件位置:** `examples\research_projects\movement-pruning\masked_run_squad.py:607`
- **数据流:** 用户控制的路径参数传递给torch.load()，加载恶意模型文件可导致任意代码执行
- **判断理由:** 根据bandit静态分析结果，第607行存在不安全的PyTorch加载操作，与第165、166行类似，torch.load()默认使用pickle反序列化，存在任意代码执行风险。

**代码片段:**
```
（源代码未完整显示，但根据bandit报告，第607行存在torch.load()调用）
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B0F554F2 - 不安全的eval()函数使用

- **严重等级:** CRITICAL
- **文件位置:** `examples\research_projects\pplm\run_pplm_discrim_train.py:291`
- **数据流:** 用户输入可能通过命令行参数或配置文件传递到eval()函数
- **判断理由:** eval()函数会执行任意Python代码，如果传入的数据包含恶意代码，将导致远程代码执行。应使用ast.literal_eval()替代。

**代码片段:**
```
（根据bandit报告，该行使用了eval()函数，但源代码片段被截断，无法获取完整代码）
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-79EBE3C7 - 不安全的eval()函数使用

- **严重等级:** CRITICAL
- **文件位置:** `examples\research_projects\pplm\run_pplm_discrim_train.py:340`
- **数据流:** 用户输入可能通过命令行参数或配置文件传递到eval()函数
- **判断理由:** 与第291行相同的问题，eval()函数存在严重安全风险，可能导致任意代码执行。

**代码片段:**
```
（根据bandit报告，该行使用了eval()函数，但源代码片段被截断，无法获取完整代码）
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-D56E4769 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `examples/research_projects/rag/consolidate_rag_checkpoint.py:48`
- **数据流:** 用户通过命令行参数 --generator_tokenizer_name_or_path 传入 generator_tokenizer_name_or_path（若未指定则默认为 generator_name_or_path），该参数直接传递给 AutoTokenizer.from_pretrained() 方法，未指定 revision 参数。
- **判断理由:** 与第32行类似，generator_tokenizer_name_or_path 由用户输入控制，且未锁定 revision。攻击者可利用此漏洞诱导用户下载恶意分词器，可能包含恶意代码或导致数据泄露。

**代码片段:**
```
gen_tokenizer = AutoTokenizer.from_pretrained(generator_tokenizer_name_or_path)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-85C80D41 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `examples/research_projects/rag/consolidate_rag_checkpoint.py:50`
- **数据流:** 用户通过命令行参数 --question_encoder_tokenizer_name_or_path 传入 question_encoder_tokenizer_name_or_path（若未指定则默认为 question_encoder_name_or_path），该参数直接传递给 AutoTokenizer.from_pretrained() 方法，未指定 revision 参数。
- **判断理由:** 与第32行类似，question_encoder_tokenizer_name_or_path 由用户输入控制，且未锁定 revision。攻击者可利用此漏洞诱导用户下载恶意分词器。

**代码片段:**
```
question_encoder_tokenizer = AutoTokenizer.from_pretrained(question_encoder_tokenizer_name_or_path)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-8722F5BD - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/research_projects/rag/eval_rag.py:294`
- **数据流:** 用户通过命令行参数 --model_name_or_path 指定模型名称或路径，该参数直接传递给 from_pretrained() 方法，没有指定 revision 参数来固定模型版本
- **判断理由:** 使用 from_pretrained() 从 Hugging Face Hub 下载模型时，如果没有指定 revision 参数，会自动下载最新版本的模型。这可能导致供应链攻击，因为攻击者可以上传恶意版本的模型到 Hub，而用户会在不知情的情况下下载并加载恶意模型。Bandit 工具已检测到该问题 (B615)。

**代码片段:**
```
from_pretrained()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-88105417 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/research_projects/rag-end2end-retriever/eval_rag.py:294`
- **数据流:** 模型加载时未指定revision参数，直接从Hugging Face Hub下载模型权重，可能加载到被恶意篡改的模型版本
- **判断理由:** Bandit工具检测到B615漏洞：使用from_pretrained()方法从Hugging Face Hub加载模型时，没有通过revision参数固定模型版本。这可能导致加载到被恶意修改的模型权重，引入后门或恶意代码。攻击者可能上传包含恶意代码的模型版本，如果用户不固定版本号，可能自动下载到被污染的版本。

**代码片段:**
```
from transformers import BartForConditionalGeneration, RagRetriever, RagSequenceForGeneration, RagTokenForGeneration
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-97B8CCD6 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\research_projects\robust-speech-event\eval.py:74`
- **数据流:** 用户通过命令行参数 --model_id 传入模型标识符，该参数直接传递给 from_pretrained() 函数，未指定 revision 参数，导致可能加载恶意版本的模型。
- **判断理由:** from_pretrained() 未指定 revision 参数，默认加载最新版本。攻击者可能上传恶意模型到 Hugging Face Hub，通过社会工程学诱导用户使用特定模型 ID，从而执行任意代码或窃取数据。

**代码片段:**
```
feature_extractor = AutoFeatureExtractor.from_pretrained(args.model_id)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-A1F2A118 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples\research_projects\robust-speech-event\eval.py:82`
- **数据流:** 用户通过命令行参数 --model_id 传入模型标识符，该参数直接传递给 pipeline() 函数，未指定 revision 参数，导致可能加载恶意版本的模型。
- **判断理由:** pipeline() 未指定 revision 参数，默认加载最新版本。攻击者可能上传恶意模型到 Hugging Face Hub，通过社会工程学诱导用户使用特定模型 ID，从而执行任意代码或窃取数据。

**代码片段:**
```
asr = pipeline("automatic-speech-recognition", model=args.model_id, device=args.device)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B6C6E7E5 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `examples/research_projects/robust-speech-event/run_speech_recognition_ctc_streaming.py:374`
- **数据流:** load_dataset() is called without specifying a revision parameter, allowing potential supply chain attacks where a malicious actor could update the dataset on the Hub.
- **判断理由:** Bandit B615: load_dataset() without revision pinning means the code will always download the latest version of the dataset. If the dataset repository is compromised or the maintainer pushes malicious changes, the code will automatically fetch the malicious version without any version control or integrity check.

**代码片段:**
```
load_dataset(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-FE03A1E1 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `examples/research_projects/robust-speech-event/run_speech_recognition_ctc_streaming.py:397`
- **数据流:** from_pretrained() is called without specifying a revision parameter, allowing potential supply chain attacks where a malicious actor could update the model on the Hub.
- **判断理由:** Bandit B615: from_pretrained() without revision pinning means the code will always download the latest version of the model. If the model repository is compromised or the maintainer pushes malicious changes, the code will automatically fetch the malicious version without any version control or integrity check.

**代码片段:**
```
from_pretrained(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-F82E6B74 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `examples/research_projects/robust-speech-event/run_speech_recognition_ctc_streaming.py:467`
- **数据流:** from_pretrained() is called without specifying a revision parameter, allowing potential supply chain attacks where a malicious actor could update the model on the Hub.
- **判断理由:** Bandit B615: Same vulnerability as line 397. The from_pretrained() call at line 467 does not pin a specific revision, making it susceptible to supply chain attacks.

**代码片段:**
```
from_pretrained(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-54B86C0E - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `examples/research_projects/robust-speech-event/run_speech_recognition_ctc_streaming.py:508`
- **数据流:** from_pretrained() is called without specifying a revision parameter, allowing potential supply chain attacks where a malicious actor could update the model on the Hub.
- **判断理由:** Bandit B615: Same vulnerability as line 397. The from_pretrained() call at line 508 does not pin a specific revision, making it susceptible to supply chain attacks.

**代码片段:**
```
from_pretrained(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-277A62D6 - 不安全的反序列化 - PyTorch模型加载

- **严重等级:** CRITICAL
- **文件位置:** `examples/research_projects/seq2seq-distillation/convert_pl_checkpoint_to_hf.py:59`
- **数据流:** 用户通过命令行参数pl_ckpt_path传入文件路径 -> 第48行判断是否为文件或目录 -> 第52-55行获取ckpt文件列表 -> 第59行使用torch.load()加载ckpt文件
- **判断理由:** torch.load()默认使用pickle进行反序列化，可以执行任意代码。攻击者可以构造恶意的.ckpt文件，当用户加载该文件时，会在服务器上执行任意代码。虽然map_location='cpu'限制了设备映射，但无法防止pickle反序列化攻击。

**代码片段:**
```
state_dicts = [sanitize(torch.load(x, map_location="cpu")["state_dict"]) for x in ckpt_files]
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-CCB16DAB - 不安全的Hugging Face Hub下载 - 未固定版本

- **严重等级:** HIGH
- **文件位置:** `examples/research_projects/seq2seq-distillation/convert_pl_checkpoint_to_hf.py:48`
- **数据流:** 用户通过命令行参数hf_src_model_dir传入模型路径 -> 第48行直接传递给from_pretrained() -> 如果路径是Hub模型ID，会从Hub下载模型
- **判断理由:** from_pretrained()未指定revision参数，当hf_src_model_dir是Hugging Face Hub上的模型ID时，会下载最新版本。攻击者可以上传恶意版本到该模型仓库，导致用户加载恶意模型。应使用revision参数固定到特定commit或tag。

**代码片段:**
```
hf_model = AutoModelForSeq2SeqLM.from_pretrained(hf_src_model_dir)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-8AAECFD1 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/research_projects/seq2seq-distillation/run_eval.py:43`
- **数据流:** 用户通过命令行参数model_name传入模型名称 -> 直接传递给from_pretrained()方法 -> 从Hugging Face Hub下载tokenizer配置
- **判断理由:** 与第39行相同的问题，tokenizer的加载也未指定revision参数。攻击者可以上传包含恶意代码的tokenizer配置文件（如tokenizer_config.json），在加载时执行任意代码。model_name参数完全由用户控制，存在供应链攻击风险。

**代码片段:**
```
tokenizer = AutoTokenizer.from_pretrained(model_name)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-6485AA7C - 代码注入

- **严重等级:** CRITICAL
- **文件位置:** `examples\research_projects\visual_bert\extracting_data.py:137`
- **数据流:** 用户通过命令行参数 -s/--subset_list 指定文件路径 -> 文件被打开并传递给 tryload 函数 -> 如果 JSON 解析失败，则执行 eval(stream.read())，将文件内容作为 Python 代码执行
- **判断理由:** tryload 函数在 JSON 解析失败后，使用 eval() 函数执行文件内容。攻击者可以构造一个恶意文件作为 subset_list 参数，其中包含任意 Python 代码，导致远程代码执行。这是典型的代码注入漏洞，危害极大。

**代码片段:**
```
def tryload(stream):
    try:
        data = json.load(stream)
        try:
            data = list(data.keys())
        except Exception:
            data = [d["img_id"] for d in data]
    except Exception:
        try:
            data = eval(stream.read())
        except Exception:
            data = stream.read().split("\n")
    return data
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-081F79FF - 命令注入

- **严重等级:** HIGH
- **文件位置:** `examples\research_projects\visual_bert\extracting_data.py:137`
- **数据流:** 用户通过命令行参数 -s/--subset_list 指定文件路径 -> 文件被打开并传递给 tryload 函数 -> 如果 JSON 解析失败，则执行 eval(stream.read())，将文件内容作为 Python 代码执行
- **判断理由:** eval() 函数可以执行任意 Python 代码，包括系统命令（如 os.system、subprocess 等）。攻击者可以通过控制 subset_list 文件内容来执行任意系统命令，导致命令注入。

**代码片段:**
```
def tryload(stream):
    ...
    except Exception:
        try:
            data = eval(stream.read())
        except Exception:
            data = stream.read().split("\n")
    return data
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-6FF888E8 - 不安全的反序列化

- **严重等级:** HIGH
- **文件位置:** `examples\research_projects\visual_bert\extracting_data.py:137`
- **数据流:** 用户通过命令行参数 -s/--subset_list 指定文件路径 -> 文件被打开并传递给 tryload 函数 -> 如果 JSON 解析失败，则执行 eval(stream.read())，将文件内容作为 Python 代码执行
- **判断理由:** eval() 本质上是一种不安全的反序列化方式，它可以将任意 Python 表达式从字符串转换为可执行对象。攻击者可以构造恶意的序列化数据，在反序列化过程中执行任意代码。

**代码片段:**
```
def tryload(stream):
    ...
    except Exception:
        try:
            data = eval(stream.read())
        except Exception:
            data = stream.read().split("\n")
    return data
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-443DC19F - 不安全的PyTorch模型加载

- **严重等级:** CRITICAL
- **文件位置:** `examples\research_projects\visual_bert\modeling_frcnn.py:1750`
- **数据流:** 静态工具检测到第1750行存在不安全的PyTorch load调用，但具体调用位置在导入的load_checkpoint函数中。用户输入可能通过模型权重文件路径传入，最终传递给torch.load()函数。
- **判断理由:** Bandit静态分析工具检测到B614漏洞，表明代码中使用了不安全的PyTorch load函数。PyTorch的torch.load()函数默认使用pickle反序列化，可以执行任意代码。如果攻击者能够控制加载的模型文件（例如通过远程URL或用户上传），则可能导致远程代码执行。虽然具体调用位置在导入的utils模块中，但该文件导入了load_checkpoint函数，该函数很可能调用了torch.load()。

**代码片段:**
```
from utils import WEIGHTS_NAME, Config, cached_path, hf_bucket_url, is_remote_url, load_checkpoint
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-61E8DDC8 - 缺少超时设置的HTTP请求

- **严重等级:** MEDIUM
- **文件位置:** `examples/research_projects/visual_bert/utils.py:271`
- **数据流:** 函数cached_path中调用requests.get()未设置timeout参数，攻击者可以发起慢速连接攻击导致资源耗尽。
- **判断理由:** 未设置超时的HTTP请求可能导致程序无限期等待响应，造成资源耗尽或拒绝服务。

**代码片段:**
```
requests.get(url_or_filename, ...)  # 未设置timeout参数
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-432BA046 - 不安全的tarfile.extractall

- **严重等级:** HIGH
- **文件位置:** `examples/research_projects/visual_bert/utils.py:478`
- **数据流:** 从网络下载的tar文件直接解压到本地路径，未对压缩包中的文件路径进行验证。
- **判断理由:** tarfile.extractall()默认不会检查压缩包中的文件路径，攻击者可以构造包含路径遍历（如../../etc/passwd）的恶意tar文件，覆盖任意系统文件。

**代码片段:**
```
tar.extractall(path=extraction_path)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-1FA9F0FC - 不安全的tarfile.extractall

- **严重等级:** HIGH
- **文件位置:** `examples/research_projects/visual_bert/utils.py:482`
- **数据流:** 从网络下载的tar文件直接解压到本地路径，未对压缩包中的文件路径进行验证。
- **判断理由:** 与第478行相同，存在路径遍历攻击风险。

**代码片段:**
```
tar.extractall(path=extraction_path)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-9DE249F6 - 不安全的eval函数使用

- **严重等级:** CRITICAL
- **文件位置:** `examples/research_projects/visual_bert/utils.py:496`
- **数据流:** 从文件中读取每一行内容后直接传递给eval()执行，攻击者可以构造恶意的Python代码字符串。
- **判断理由:** eval()会执行任意Python代码，如果攻击者能够控制文件内容，将导致远程代码执行。应使用ast.literal_eval()替代。

**代码片段:**
```
eval(line.strip())
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-D381E8F9 - 缺少超时设置的HTTP请求

- **严重等级:** MEDIUM
- **文件位置:** `examples/research_projects/visual_bert/utils.py:498`
- **数据流:** HTTP请求未设置超时，可能导致资源耗尽。
- **判断理由:** 与第271行相同，存在拒绝服务风险。

**代码片段:**
```
requests.get(url, ...)  # 未设置timeout参数
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-16DF6726 - 不安全的eval函数使用

- **严重等级:** CRITICAL
- **文件位置:** `examples/research_projects/visual_bert/utils.py:505`
- **数据流:** 从文件中读取每一行内容后直接传递给eval()执行。
- **判断理由:** 与第496行相同，存在远程代码执行风险。

**代码片段:**
```
eval(line.strip())
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B83D8D5B - 缺少超时设置的HTTP请求

- **严重等级:** MEDIUM
- **文件位置:** `examples/research_projects/visual_bert/utils.py:513`
- **数据流:** HTTP请求未设置超时。
- **判断理由:** 与第271行相同，存在拒绝服务风险。

**代码片段:**
```
requests.get(url, ...)  # 未设置timeout参数
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-9C35A8C4 - 不安全的反序列化 - Pickle

- **严重等级:** CRITICAL
- **文件位置:** `examples/research_projects/visual_bert/utils.py:524`
- **数据流:** 从文件中加载pickle数据，未对数据来源进行验证。
- **判断理由:** 与第95行相同，pickle.load()反序列化不受信任数据可导致任意代码执行。

**代码片段:**
```
pkl.load(f)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-6AEBD98B - 不安全的PyTorch模型加载

- **严重等级:** CRITICAL
- **文件位置:** `examples\research_projects\vqgan-clip\loaders.py:67`
- **数据流:** 用户控制的ckpt参数(第66行)直接传入torch.load()(第67行)，未进行任何校验或限制
- **判断理由:** 与第23行相同，torch.load()使用pickle反序列化，存在任意代码执行风险。ckpt参数来自函数参数(第66行)，如果被外部控制则存在严重风险。

**代码片段:**
```
pl_sd = torch.load(ckpt, map_location="cpu")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-3A15EAB8 - 不安全的动态导入

- **严重等级:** HIGH
- **文件位置:** `examples\research_projects\vqgan-clip\loaders.py:37`
- **数据流:** config['target']字符串(第42行)通过get_obj_from_str()(第36行)分割后用于动态导入模块和获取属性
- **判断理由:** instantiate_from_config()(第41行)从配置中获取'target'键值，该值可能来自不可信的配置文件。攻击者可以通过控制配置文件中的'target'字段，导入任意Python模块并执行任意代码。

**代码片段:**
```
return getattr(importlib.import_module(module, package=None), cls)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-38384AF7 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `examples/research_projects/wav2vec2/run_pretrain.py:318`
- **数据流:** 用户通过命令行参数或配置文件指定dataset_name，该参数直接传递给load_dataset()函数，未指定revision参数
- **判断理由:** 与第298行相同的问题，load_dataset()调用未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
load_dataset()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-10DD3CDB - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `examples/research_projects/wav2vec2/run_pretrain.py:324`
- **数据流:** 用户通过命令行参数或配置文件指定dataset_name，该参数直接传递给load_dataset()函数，未指定revision参数
- **判断理由:** 与第298行相同的问题，load_dataset()调用未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
load_dataset()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-51BB3C57 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `examples/research_projects/xtreme-s/run_xtreme_s.py:501`
- **数据流:** load_dataset() function called without specifying a revision parameter, allowing potential supply chain attacks through malicious model updates on Hugging Face Hub
- **判断理由:** The load_dataset() call at line 501 does not pin a specific revision/commit hash. This means the dataset could be silently updated by the maintainer or compromised, leading to potential code execution or data poisoning attacks when the dataset is loaded.

**代码片段:**
```
load_dataset()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-03359254 - 代码注入

- **严重等级:** CRITICAL
- **文件位置:** `examples/tensorflow/benchmarking/run_benchmark_tf.py:32`
- **数据流:** 异常对象e的字符串表示被分割后，最后一个元素通过eval()执行。异常消息可能包含用户可控的输入（如命令行参数），攻击者可通过构造恶意参数触发异常，使异常消息中包含恶意Python代码，从而在eval()中执行任意代码。
- **判断理由:** 使用eval()执行动态内容，且输入源为异常对象的字符串表示。异常消息可能包含用户输入（如通过--no_xxx参数），攻击者可以构造特殊参数使异常消息中包含恶意Python代码，导致任意代码执行。应使用ast.literal_eval()安全地解析Python字面量，或使用其他安全的解析方式。

**代码片段:**
```
depreciated_args = eval(str(e).split(" ")[-1])
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B810A927 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/tensorflow/contrastive-image-text/run_clip.py:353`
- **数据流:** 用户通过命令行参数指定model_name_or_path/vision_model_name_or_path/text_model_name_or_path，这些参数直接传递给from_pretrained()方法，未指定revision参数
- **判断理由:** from_pretrained()从Hugging Face Hub加载预训练模型时未指定revision参数，默认使用最新版本。攻击者可能通过篡改Hub上的模型版本注入恶意代码或后门模型，导致模型被投毒。

**代码片段:**
```
from_pretrained()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-E6CF57CC - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/tensorflow/contrastive-image-text/run_clip.py:361`
- **数据流:** 用户通过命令行参数指定model_name_or_path/vision_model_name_or_path/text_model_name_or_path，这些参数直接传递给from_pretrained()方法，未指定revision参数
- **判断理由:** 与第353行相同，另一个from_pretrained()调用同样未指定revision参数，存在相同风险。

**代码片段:**
```
from_pretrained()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-727DC2F6 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/tensorflow/language-modeling/run_clm.py:312`
- **数据流:** 用户通过命令行参数指定dataset_name，直接传递给load_dataset()函数，未指定revision参数
- **判断理由:** 与第296行类似，load_dataset()调用未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
load_dataset(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-35839C82 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/tensorflow/language-modeling/run_clm.py:387`
- **数据流:** 用户通过命令行参数指定model_name_or_path，直接传递给from_pretrained()方法，未指定revision参数
- **判断理由:** 与第369行类似，from_pretrained()调用未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
from_pretrained(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-C67CBA84 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/tensorflow/language-modeling/run_clm.py:492`
- **数据流:** 用户通过命令行参数指定model_name_or_path，直接传递给from_pretrained()方法，未指定revision参数
- **判断理由:** 与第369行类似，from_pretrained()调用未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
from_pretrained(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-5AA372F4 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/tensorflow/language-modeling/run_mlm.py:313`
- **数据流:** 用户通过命令行参数指定dataset_name和dataset_config_name，这些参数直接传递给load_dataset()函数，未指定固定的revision版本
- **判断理由:** load_dataset()调用未指定固定的revision版本，攻击者可能通过篡改Hub上的数据集来注入恶意代码，导致供应链攻击

**代码片段:**
```
load_dataset(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-6CBFB2C4 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/tensorflow/language-modeling/run_mlm.py:337`
- **数据流:** 用户通过命令行参数指定dataset_name和dataset_config_name，这些参数直接传递给load_dataset()函数，未指定固定的revision版本
- **判断理由:** load_dataset()调用未指定固定的revision版本，攻击者可能通过篡改Hub上的数据集来注入恶意代码，导致供应链攻击

**代码片段:**
```
load_dataset(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-FDCFAF94 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/tensorflow/language-modeling-tpu/prepare_tfrecord_shards.py:117`
- **数据流:** 用户通过命令行参数 --dataset_name 和 --dataset_config 控制数据集名称和配置，直接传递给 datasets.load_dataset() 函数，未指定 revision 参数固定版本。
- **判断理由:** datasets.load_dataset() 未指定 revision 参数，会从 Hugging Face Hub 下载最新版本的数据集。攻击者可能通过篡改 Hub 上的数据集（如更新恶意代码）导致供应链攻击。当 trust_remote_code=True 时，风险更高，因为数据集可能包含可执行代码。

**代码片段:**
```
dataset = datasets.load_dataset(
    args.dataset_name, args.dataset_config, split=args.split, trust_remote_code=args.trust_remote_code
)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-F02FFBB7 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/tensorflow/language-modeling-tpu/prepare_tfrecord_shards.py:126`
- **数据流:** 用户通过命令行参数 --tokenizer_name_or_path 控制 tokenizer 名称或路径，直接传递给 AutoTokenizer.from_pretrained() 函数，未指定 revision 参数固定版本。
- **判断理由:** AutoTokenizer.from_pretrained() 未指定 revision 参数，会从 Hugging Face Hub 下载最新版本的 tokenizer。攻击者可能通过篡改 Hub 上的 tokenizer 文件（如修改 tokenizer_config.json 或 tokenizer.json）导致供应链攻击。tokenizer 加载过程中可能执行代码，存在远程代码执行风险。

**代码片段:**
```
tokenizer = AutoTokenizer.from_pretrained(args.tokenizer_name_or_path)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-45B6B981 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `examples/tensorflow/language-modeling-tpu/run_mlm.py:229`
- **数据流:** 用户通过命令行参数 --pretrained_model_config 传入 args.pretrained_model_config，该值直接传递给 AutoConfig.from_pretrained()，未指定 revision 参数，可能下载恶意或未经验证的模型配置。
- **判断理由:** 与 line 228 类似，from_pretrained() 方法未指定 revision，用户输入可控，存在供应链攻击风险。

**代码片段:**
```
config = AutoConfig.from_pretrained(args.pretrained_model_config)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-2BCEF91E - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/tensorflow/language-modeling-tpu/train_unigram.py:81`
- **数据流:** 用户通过命令行参数 --dataset_name 和 --dataset_config 控制数据集名称和配置，直接传递给 datasets.load_dataset() 函数，未指定 revision 参数来固定数据集版本。攻击者可能通过修改远程仓库内容或诱导用户使用恶意数据集名称来加载被篡改的数据集。
- **判断理由:** datasets.load_dataset() 默认从 Hugging Face Hub 下载最新版本的数据集，未指定 revision 参数意味着每次运行可能加载不同版本的数据集。结合 trust_remote_code=True 选项（由用户控制），攻击者可能通过控制数据集仓库内容或利用数据集名称的拼写错误（typosquatting）来执行恶意代码。这属于供应链攻击的一种形式，可能导致任意代码执行。

**代码片段:**
```
dataset = datasets.load_dataset(
    args.dataset_name, args.dataset_config, split="train", trust_remote_code=args.trust_remote_code
)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-6ECC1B43 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/tensorflow/question-answering/run_qa.py:327`
- **数据流:** 用户通过命令行参数或配置文件指定dataset_name，该参数直接传递给load_dataset()函数，未指定revision参数固定数据集版本。攻击者可以上传恶意版本的数据集到同一名称下，导致下载恶意数据集。
- **判断理由:** load_dataset()调用未指定revision参数，默认使用最新版本。如果攻击者控制了Hugging Face Hub上的数据集仓库，可以上传恶意版本，导致用户下载并执行恶意代码或数据。

**代码片段:**
```
load_dataset(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-93BC993E - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/tensorflow/question-answering/run_qa.py:346`
- **数据流:** 用户通过命令行参数或配置文件指定dataset_name，该参数直接传递给load_dataset()函数，未指定revision参数固定数据集版本。攻击者可以上传恶意版本的数据集到同一名称下，导致下载恶意数据集。
- **判断理由:** load_dataset()调用未指定revision参数，默认使用最新版本。如果攻击者控制了Hugging Face Hub上的数据集仓库，可以上传恶意版本，导致用户下载并执行恶意代码或数据。

**代码片段:**
```
load_dataset(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-405FA8BF - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `examples/tensorflow/summarization/run_summarization.py:364`
- **数据流:** 用户通过命令行参数或配置文件指定dataset_name和dataset_config_name，这些参数直接传递给load_dataset()函数，没有指定具体的revision版本号，导致从Hugging Face Hub下载的数据集可能被恶意篡改
- **判断理由:** load_dataset()函数在未指定revision参数时，默认使用最新版本的数据集。攻击者可能通过上传恶意版本的数据集来实施供应链攻击，导致用户下载并执行恶意代码或使用被污染的数据进行模型训练。bandit工具检测到B615规则，表明存在不安全的Hugging Face Hub下载操作。

**代码片段:**
```
load_dataset()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-C2455869 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `examples/tensorflow/text-classification/run_glue.py:251`
- **数据流:** load_dataset() is called without specifying a revision parameter, which means it will download the latest version of the dataset from Hugging Face Hub. This could lead to supply chain attacks if a malicious actor updates the dataset repository.
- **判断理由:** Bandit static analysis tool detected that load_dataset() is called without revision pinning. Without specifying a specific revision (commit hash, tag, or branch), the code will always fetch the latest version of the dataset, which could be compromised or contain malicious content. This is a supply chain security risk.

**代码片段:**
```
load_dataset()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-F1E46E4A - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/tensorflow/token-classification/run_ner.py:238`
- **数据流:** 用户通过命令行参数指定dataset_name或dataset_config_name，这些参数直接传递给load_dataset()函数，没有强制指定固定的revision版本。攻击者可以上传恶意版本的数据集到Hugging Face Hub，如果用户下载了恶意版本，可能导致代码执行或数据投毒。
- **判断理由:** load_dataset()调用没有使用revision参数固定数据集版本，默认使用最新版本。如果攻击者控制了Hugging Face仓库并上传恶意版本，用户将自动下载恶意版本，可能导致任意代码执行（因为数据集可以包含Python代码）。

**代码片段:**
```
load_dataset()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-6DCC2BBD - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/tensorflow/token-classification/run_ner.py:313`
- **数据流:** 用户通过model_args.model_name_or_path指定模型名称或路径，该参数直接传递给from_pretrained()方法，没有强制指定固定的revision版本。
- **判断理由:** 与第306行相同，另一个from_pretrained()调用也没有指定revision参数，存在同样的供应链攻击风险。

**代码片段:**
```
from_pretrained()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-63280225 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/tensorflow/token-classification/run_ner.py:331`
- **数据流:** 用户通过model_args.model_name_or_path指定模型名称或路径，该参数直接传递给from_pretrained()方法，没有强制指定固定的revision版本。
- **判断理由:** 与第306行相同，另一个from_pretrained()调用也没有指定revision参数，存在同样的供应链攻击风险。

**代码片段:**
```
from_pretrained()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-261C3414 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/tensorflow/token-classification/run_ner.py:339`
- **数据流:** 用户通过model_args.model_name_or_path指定模型名称或路径，该参数直接传递给from_pretrained()方法，没有强制指定固定的revision版本。
- **判断理由:** 与第306行相同，另一个from_pretrained()调用也没有指定revision参数，存在同样的供应链攻击风险。

**代码片段:**
```
from_pretrained()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-11C1E40B - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/tensorflow/token-classification/run_ner.py:412`
- **数据流:** 用户通过model_args.model_name_or_path指定模型名称或路径，该参数直接传递给from_pretrained()方法，没有强制指定固定的revision版本。
- **判断理由:** 与第306行相同，另一个from_pretrained()调用也没有指定revision参数，存在同样的供应链攻击风险。

**代码片段:**
```
from_pretrained()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-3CD83E49 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/tensorflow/translation/run_translation.py:331`
- **数据流:** 用户通过命令行参数或配置文件传入dataset_name和dataset_config_name，这些参数直接传递给load_dataset()函数，没有指定固定的revision版本号，导致从Hugging Face Hub下载的数据集可能被恶意篡改
- **判断理由:** load_dataset()函数在未指定revision参数时，默认使用最新版本的数据集。攻击者如果能够控制Hugging Face Hub上的数据集仓库，可以上传恶意版本的数据集，导致用户下载到被篡改的数据。这属于供应链攻击的一种形式。

**代码片段:**
```
load_dataset()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B58A086A - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `examples/tensorflow/translation/run_translation.py:346`
- **数据流:** 用户通过命令行参数或配置文件传入dataset_name和dataset_config_name，这些参数直接传递给load_dataset()函数，没有指定固定的revision版本号，导致从Hugging Face Hub下载的数据集可能被恶意篡改
- **判断理由:** 与第331行相同的漏洞，load_dataset()函数在未指定revision参数时，默认使用最新版本的数据集。攻击者如果能够控制Hugging Face Hub上的数据集仓库，可以上传恶意版本的数据集，导致用户下载到被篡改的数据。这属于供应链攻击的一种形式。

**代码片段:**
```
load_dataset()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-81D10F68 - SSRF (Server-Side Request Forgery) - 请求未设置超时

- **严重等级:** MEDIUM
- **文件位置:** `src\transformers\image_processing_base.py:543`
- **数据流:** 静态工具报告第543行存在requests调用未设置timeout参数。虽然代码片段未完整显示具体调用，但根据bandit检测结果，该行使用了requests库发起HTTP请求，但未指定timeout参数，可能导致请求无限期阻塞。
- **判断理由:** 根据bandit规则B113，使用requests库发起HTTP请求时必须设置timeout参数，否则可能导致程序挂起或资源耗尽。虽然该漏洞严重程度为medium，但在网络请求中缺少超时设置可能被利用进行拒绝服务攻击，或导致资源泄露。

**代码片段:**
```
requests without timeout
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-FB5ED182 - 不安全的PyTorch模型加载

- **严重等级:** HIGH
- **文件位置:** `src/transformers/modeling_flax_pytorch_utils.py:77`
- **数据流:** 用户提供的pytorch_checkpoint_path参数 -> pt_path变量 -> torch.load()函数调用
- **判断理由:** torch.load()默认使用pickle反序列化，可以执行任意代码。虽然代码中尝试使用weights_only=True参数来缓解，但该参数仅在PyTorch 1.13及以上版本可用，且通过条件判断`is_torch_greater_or_equal_than_1_13`来决定是否启用。在旧版本PyTorch中，weights_only_kwarg为空字典，导致完全不受保护。攻击者可以构造恶意的.pt文件，在加载时执行任意代码。

**代码片段:**
```
pt_state_dict = torch.load(pt_path, map_location="cpu", **weights_only_kwarg)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-CA625BBD - Missing Timeout in HTTP Request

- **严重等级:** MEDIUM
- **文件位置:** `src\transformers\safetensors_conversion.py:45`
- **数据流:** requests.post调用没有设置timeout参数，可能导致请求被无限期阻塞。
- **判断理由:** 根据bandit检测结果B113，requests调用缺少timeout参数。这可能导致应用程序在等待响应时被挂起，造成资源耗尽或拒绝服务攻击。

**代码片段:**
```
response = requests.post(
    sse_data_url,
    stream=True,
    params=hash_data,
    json={"event_id": event_id, **payload, **hash_data},
)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-31281D82 - Missing Timeout in HTTP Request

- **严重等级:** MEDIUM
- **文件位置:** `src\transformers\safetensors_conversion.py:55`
- **数据流:** requests.get调用没有设置timeout参数，可能导致连接被无限期阻塞。
- **判断理由:** 根据bandit检测结果B113，requests调用缺少timeout参数。这可能导致应用程序在等待响应时被挂起，造成资源耗尽或拒绝服务攻击。

**代码片段:**
```
with requests.get(sse_url, stream=True, params=hash_data) as sse_connection:
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-972246FF - Sensitive Information Exposure via HTTP Request

- **严重等级:** HIGH
- **文件位置:** `src\transformers\safetensors_conversion.py:44`
- **数据流:** payload中包含token（用户认证令牌）和model_id，这些敏感信息通过HTTP POST请求发送到外部服务safetensors-convert.hf.space。如果该服务不安全或通信被拦截，可能导致token泄露。
- **判断理由:** 用户提供的token（API密钥）被直接作为payload的一部分发送到外部HTTP端点。虽然使用了HTTPS，但token作为敏感凭证不应传递给第三方服务，除非有明确的信任关系和安全措施。

**代码片段:**
```
response = requests.post(
    sse_data_url,
    stream=True,
    params=hash_data,
    json={"event_id": event_id, **payload, **hash_data},
)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-278152A8 - Insecure Direct Object Reference (IDOR)

- **严重等级:** MEDIUM
- **文件位置:** `src\transformers\safetensors_conversion.py:80`
- **数据流:** 函数检查PR作者是否为'SFConvertBot'，但仅当仓库不是private时。对于private仓库，任何用户创建的PR都会被接受，可能导致未授权的PR被引用。
- **判断理由:** 对于私有仓库，代码跳过了作者检查（not private条件），这意味着任何用户创建的PR都可能被接受。攻击者可以创建一个恶意PR，其内容被后续的auto_conversion函数使用，可能导致加载恶意模型文件。

**代码片段:**
```
if pr is None or (not private and pr.author != "SFConvertBot"):
    spawn_conversion(token, private, model_id)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-C6E7A77E - 不安全的反序列化 (Unsafe PyTorch load)

- **严重等级:** HIGH
- **文件位置:** `src/transformers/trainer.py:2840`
- **数据流:** 从文件系统加载模型权重文件 -> torch.load() 反序列化 -> 模型加载
- **判断理由:** torch.load() 默认使用 pickle 进行反序列化，如果加载的模型文件来自不可信来源或被篡改，攻击者可以构造恶意的 pickle 数据导致任意代码执行。Bandit 工具检测到该行使用了不安全的 PyTorch 加载方式。

**代码片段:**
```
torch.load(...)  # 未指定 weights_only=True
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-C049D9F2 - 不安全的反序列化 (Unsafe PyTorch load)

- **严重等级:** HIGH
- **文件位置:** `src/transformers/trainer.py:3105`
- **数据流:** 从文件系统加载模型权重文件 -> torch.load() 反序列化 -> 模型加载
- **判断理由:** torch.load() 默认使用 pickle 进行反序列化，如果加载的模型文件来自不可信来源或被篡改，攻击者可以构造恶意的 pickle 数据导致任意代码执行。Bandit 工具检测到该行使用了不安全的 PyTorch 加载方式。

**代码片段:**
```
torch.load(...)  # 未指定 weights_only=True
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-D25DF9B0 - 不安全的代码执行

- **严重等级:** CRITICAL
- **文件位置:** `src\transformers\agents\default_tools.py:115`
- **数据流:** 用户输入通过'code'参数传入forward方法 -> 直接传递给evaluate_python_code函数执行 -> 返回执行结果
- **判断理由:** PythonInterpreterTool.forward方法接收用户输入的代码并直接传递给evaluate_python_code执行。虽然限制了可导入的模块列表，但用户仍然可以执行任意Python代码，包括文件操作、网络请求等危险操作。这是一个典型的代码注入漏洞，攻击者可以执行任意Python代码，可能导致远程代码执行(RCE)。

**代码片段:**
```
def forward(self, code):
    output = str(
        evaluate_python_code(code, static_tools=self.available_tools, authorized_imports=self.authorized_imports)
    )
    return output
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-A255FADB - 路径遍历

- **严重等级:** HIGH
- **文件位置:** `src\transformers\agents\document_question_answering.py:56`
- **数据流:** 用户通过'document'参数传入字符串路径 -> 直接传递给Image.open() -> 读取文件内容
- **判断理由:** 在encode方法中，当document参数为字符串时，直接使用Image.open()打开文件路径。如果用户传入恶意路径（如'../../etc/passwd'），可能导致任意文件读取。虽然该工具通常由内部调用，但作为公开API的一部分，存在路径遍历风险。

**代码片段:**
```
if isinstance(document, str):
    img = Image.open(document).convert("RGB")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-0491EA6E - Prompt Injection / 提示注入

- **严重等级:** HIGH
- **文件位置:** `src\transformers\agents\llm_engine.py:60`
- **数据流:** 用户输入通过messages参数传入 -> get_clean_message_list()仅验证消息格式和角色合法性，未对content内容进行任何过滤或净化 -> 直接传递给InferenceClient.chat_completion()发送给LLM
- **判断理由:** 该函数接收用户提供的messages列表，其中content字段包含用户输入。代码仅验证了消息的格式（包含role和content键）和角色合法性，但未对content内容进行任何安全过滤或净化。攻击者可以通过精心构造的prompt来操纵LLM的输出，例如注入系统指令覆盖、越狱攻击或诱导LLM泄露敏感信息。这是典型的提示注入漏洞，在LLM Agent框架中尤其危险，因为Agent可能会执行LLM生成的代码或操作。

**代码片段:**
```
def __call__(
    self, messages: List[Dict[str, str]], stop_sequences: List[str] = [], grammar: Optional[str] = None
) -> str:
    # Get clean message list
    messages = get_clean_message_list(messages, role_conversions=llama_role_conversions)
    ...
    response = self.client.chat_completion(messages, stop=stop_sequences, max_tokens=1500)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-3648EF7C - 不安全的eval/exec执行

- **严重等级:** CRITICAL
- **文件位置:** `src\transformers\agents\python_interpreter.py:1`
- **数据流:** 用户输入 -> ast.parse() -> evaluate_ast() -> 执行任意Python代码
- **判断理由:** 虽然代码使用了ast模块而不是直接使用eval/exec，但本质上仍然是一个代码执行引擎。代码中允许定义函数、类、循环等复杂结构，攻击者可以利用这些功能执行任意操作。

**代码片段:**
```
evaluate_ast函数递归执行AST节点，包括函数定义、类定义、循环等
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-328A67E7 - 不安全的网络请求

- **严重等级:** HIGH
- **文件位置:** `src\transformers\agents\python_interpreter.py:1`
- **数据流:** 用户输入 -> 解释器执行 -> 可能发起网络请求
- **判断理由:** 代码中没有限制网络相关的操作。攻击者可以通过执行Python代码发起网络请求（如使用urllib、requests等模块），导致SSRF攻击、数据泄露或对外部系统发起攻击。

**代码片段:**
```
整个解释器执行环境
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-10583212 - 不安全的Hugging Face Hub下载（无修订版本锁定）

- **严重等级:** HIGH
- **文件位置:** `src\transformers\agents\text_to_speech.py:54`
- **数据流:** 用户通过调用TextToSpeechTool的encode方法触发load_dataset，该函数从Hugging Face Hub下载数据集，但未指定revision参数锁定版本。攻击者可能通过篡改数据集仓库的默认分支内容，注入恶意代码。
- **判断理由:** 1. 数据流：encode方法被调用时（可能由用户输入触发），执行load_dataset从远程Hub下载数据集。2. 控制流：未对数据集版本进行任何校验或锁定，trust_remote_code=True允许执行数据集中的自定义代码。3. 模式匹配：bandit工具检测到B615模式，即无修订版本锁定的Hub下载。4. 上下文推理：在Hugging Face生态中，数据集仓库可能被恶意维护者或攻击者篡改，未锁定版本会导致供应链攻击风险，trust_remote_code=True进一步放大了代码执行风险。

**代码片段:**
```
embeddings_dataset = load_dataset(
                "Matthijs/cmu-arctic-xvectors", split="validation", trust_remote_code=True
            )
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-A49F2D33 - 路径遍历

- **严重等级:** HIGH
- **文件位置:** `src/transformers/commands/convert.py:67`
- **数据流:** 用户通过命令行参数--tf_checkpoint, --config, --pytorch_dump_output传入路径，这些路径直接传递给convert_tf_checkpoint_to_pytorch函数，未进行任何路径验证或清理
- **判断理由:** 同上，所有模型类型分支都存在相同的路径遍历风险，用户输入直接作为文件路径使用

**代码片段:**
```
convert_tf_checkpoint_to_pytorch(self._tf_checkpoint, self._config, self._pytorch_dump_output)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-EC0DF833 - 路径遍历

- **严重等级:** HIGH
- **文件位置:** `src/transformers/commands/convert.py:74`
- **数据流:** 用户通过命令行参数--tf_checkpoint, --config, --pytorch_dump_output传入路径，这些路径直接传递给convert_tf_checkpoint_to_pytorch函数，未进行任何路径验证或清理
- **判断理由:** 同上，所有模型类型分支都存在相同的路径遍历风险

**代码片段:**
```
convert_tf_checkpoint_to_pytorch(self._tf_checkpoint, self._config, self._pytorch_dump_output)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-09D3C231 - 路径遍历

- **严重等级:** HIGH
- **文件位置:** `src/transformers/commands/convert.py:93`
- **数据流:** 用户通过命令行参数--tf_checkpoint, --config, --pytorch_dump_output传入路径，这些路径直接传递给convert_gpt2_checkpoint_to_pytorch函数，未进行任何路径验证或清理
- **判断理由:** 同上，所有模型类型分支都存在相同的路径遍历风险

**代码片段:**
```
convert_gpt2_checkpoint_to_pytorch(self._tf_checkpoint, self._config, self._pytorch_dump_output)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B0254F04 - 代码注入（通过trust_remote_code）

- **严重等级:** HIGH
- **文件位置:** `src\transformers\commands\download.py:44`
- **数据流:** 用户通过命令行参数 --trust-remote-code 传入布尔值 -> download_command_factory 接收 -> DownloadCommand.__init__ 存储为 self._trust_remote_code -> DownloadCommand.run 中传递给 AutoModel.from_pretrained 和 AutoTokenizer.from_pretrained 的 trust_remote_code 参数
- **判断理由:** 当 trust_remote_code 设置为 True 时，HuggingFace Transformers 会从 HuggingFace Hub 下载并执行远程模型的自定义代码文件（如 modeling.py）。攻击者可以上传包含恶意代码的模型到 Hub，诱导用户下载并执行，导致任意代码执行。虽然该参数默认可能为 False，但用户可以通过命令行显式启用，且文档中已警告需审查代码，但缺乏强制性的代码审查机制，存在被恶意利用的风险。

**代码片段:**
```
AutoModel.from_pretrained(
    self._model, cache_dir=self._cache, force_download=self._force, trust_remote_code=self._trust_remote_code
)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B0626A3A - Missing Request Timeout

- **严重等级:** MEDIUM
- **文件位置:** `src/transformers/commands/lfs.py:197`
- **数据流:** 用户控制的presigned_url从msg['action']['header']获取，通过requests.put()发送HTTP请求，未设置timeout参数
- **判断理由:** requests.put()调用未设置timeout参数，可能导致请求永久挂起，造成资源耗尽或连接泄漏。攻击者可以通过提供响应缓慢的URL来发起DoS攻击。

**代码片段:**
```
r = requests.put(presigned_url, data=data)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-7A065DAB - Missing Request Timeout

- **严重等级:** MEDIUM
- **文件位置:** `src/transformers/commands/lfs.py:217`
- **数据流:** 用户控制的completion_url从msg['action']['href']获取，通过requests.post()发送HTTP请求，未设置timeout参数
- **判断理由:** requests.post()调用未设置timeout参数，可能导致请求永久挂起，造成资源耗尽或连接泄漏。攻击者可以通过提供响应缓慢的URL来发起DoS攻击。

**代码片段:**
```
r = requests.post(completion_url, json={'oid': oid, 'parts': parts})
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-25DE175E - SSRF (Server-Side Request Forgery)

- **严重等级:** HIGH
- **文件位置:** `src/transformers/commands/lfs.py:197`
- **数据流:** 用户控制的presigned_urls从msg['action']['header']解析，直接传递给requests.put()发起HTTP请求，未进行任何URL验证或白名单检查
- **判断理由:** 攻击者可以通过构造恶意的LFS消息，提供指向内部网络地址的presigned_urls，导致服务器向内部系统发起请求，可能访问内部服务、云元数据端点等敏感资源。

**代码片段:**
```
presigned_urls: List[str] = list(header.values())
...
r = requests.put(presigned_url, data=data)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-D94F9749 - SSRF (Server-Side Request Forgery)

- **严重等级:** HIGH
- **文件位置:** `src/transformers/commands/lfs.py:217`
- **数据流:** 用户控制的completion_url从msg['action']['href']获取，直接传递给requests.post()发起HTTP请求，未进行任何URL验证或白名单检查
- **判断理由:** 攻击者可以通过构造恶意的LFS消息，提供指向内部网络地址的completion_url，导致服务器向内部系统发起POST请求，可能访问内部服务或云元数据端点。

**代码片段:**
```
completion_url = msg['action']['href']
...
r = requests.post(completion_url, json={'oid': oid, 'parts': parts})
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-AA4D72BD - 路径遍历

- **严重等级:** HIGH
- **文件位置:** `src/transformers/commands/train.py:107`
- **数据流:** 用户通过命令行参数 --train_data 传入文件路径 -> args.train_data -> Processor.create_from_csv()
- **判断理由:** args.train_data 直接来自用户输入，未经过路径校验。攻击者可以传入任意文件路径（如 /etc/passwd 或 ../../secret.txt），导致读取系统敏感文件。

**代码片段:**
```
self.train_dataset = Processor.create_from_csv(
    args.train_data,
    column_label=args.column_label,
    column_text=args.column_text,
    column_id=args.column_id,
    skip_first_row=args.skip_first_row,
)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-4CD05539 - 路径遍历

- **严重等级:** HIGH
- **文件位置:** `src/transformers/commands/train.py:115`
- **数据流:** 用户通过命令行参数 --validation_data 传入文件路径 -> args.validation_data -> Processor.create_from_csv()
- **判断理由:** args.validation_data 直接来自用户输入，未经过路径校验。攻击者可以传入任意文件路径，导致读取系统敏感文件。

**代码片段:**
```
self.valid_dataset = Processor.create_from_csv(
    args.validation_data,
    column_label=args.column_label,
    column_text=args.column_text,
    column_id=args.column_id,
    skip_first_row=args.skip_first_row,
)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-C573860F - 不安全的反序列化

- **严重等级:** CRITICAL
- **文件位置:** `src\transformers\data\datasets\glue.py:125`
- **数据流:** 用户通过命令行参数或配置文件控制data_dir和cache_dir参数，这些参数被用于构造cached_features_file路径（第107-110行）。如果攻击者能够控制data_dir或cache_dir，或者能够替换缓存文件，则torch.load会加载恶意的pickle数据，导致任意代码执行。
- **判断理由:** torch.load默认使用pickle模块进行反序列化，而pickle在加载数据时会执行任意Python代码。攻击者可以通过构造恶意的缓存文件（如修改data_dir指向恶意文件或替换已有缓存文件）来触发远程代码执行。虽然文件路径中包含tokenizer类名等固定部分，但data_dir和cache_dir由用户控制，且缓存文件可能被替换，因此存在严重的安全风险。

**代码片段:**
```
self.features = torch.load(cached_features_file)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-6861EC87 - 不安全的反序列化 (Unsafe PyTorch load)

- **严重等级:** HIGH
- **文件位置:** `src\transformers\data\datasets\squad.py:151`
- **数据流:** 用户可通过控制cache_dir或data_dir参数影响cached_features_file路径，从而加载恶意构造的PyTorch文件。torch.load()默认使用pickle反序列化，可执行任意代码。
- **判断理由:** torch.load()底层使用pickle模块进行反序列化，pickle在加载恶意数据时可以执行任意Python代码。攻击者如果能控制缓存文件路径或替换缓存文件，可导致远程代码执行。虽然文件路径由内部参数构造，但cache_dir和data_dir可能受用户输入影响，且缓存文件可能被其他进程替换。建议使用torch.load(..., weights_only=True)或使用安全的序列化格式。

**代码片段:**
```
self.old_features = torch.load(cached_features_file)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-66530BAB - 不安全的动态模块加载（潜在代码注入）

- **严重等级:** HIGH
- **文件位置:** `src/transformers/models/auto/auto_factory.py:1`
- **数据流:** 用户通过pretrained_model_name_or_path参数传入模型标识符 -> 动态加载模块 -> get_class_from_dynamic_module执行远程代码
- **判断理由:** 代码导入了get_class_from_dynamic_module和resolve_trust_remote_code函数，这些函数用于从HuggingFace Hub动态加载自定义模型代码。当trust_remote_code=True时，会从远程仓库下载并执行任意Python代码。如果用户能够控制pretrained_model_name_or_path参数指向恶意仓库，可能导致远程代码执行(RCE)漏洞。虽然trust_remote_code默认为False，但该功能本质上存在安全风险。

**代码片段:**
```
from ...dynamic_module_utils import get_class_from_dynamic_module, resolve_trust_remote_code
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-349B364D - 不安全的反序列化 - PyTorch load

- **严重等级:** CRITICAL
- **文件位置:** `src/transformers/models/bert/convert_bert_pytorch_checkpoint_to_original_tf.py:104`
- **数据流:** 用户通过命令行参数 --pytorch_model_path 传入文件路径 -> args.pytorch_model_path -> torch.load() 加载并反序列化文件内容
- **判断理由:** torch.load() 默认使用 pickle 反序列化，可以执行任意代码。攻击者可以构造恶意的 .bin 文件，当用户加载该文件时，会在目标系统上执行任意代码。这是一个严重的安全漏洞，因为攻击者可以完全控制执行流程。

**代码片段:**
```
state_dict=torch.load(args.pytorch_model_path)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-AAA2C8A5 - 不安全的反序列化 (Unsafe PyTorch load)

- **严重等级:** CRITICAL
- **文件位置:** `src\transformers\models\bloom\convert_bloom_original_checkpoint_to_pytorch.py:107`
- **数据流:** 用户通过命令行参数 --bloom_checkpoint_path 传入路径 -> os.listdir() 列出目录文件 -> 文件名拼接后传入 torch.load()
- **判断理由:** torch.load() 默认使用 pickle 反序列化，可以执行任意代码。攻击者如果能够控制 checkpoint 目录中的文件（例如通过路径遍历或上传恶意文件），就可以在模型加载时执行任意 Python 代码。虽然 map_location='cpu' 限制了设备映射，但无法防止 pickle 反序列化攻击。

**代码片段:**
```
temp = torch.load(os.path.join(bloom_checkpoint_path, f_name), map_location="cpu")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-F55829C4 - 不安全的反序列化 (Unsafe PyTorch load)

- **严重等级:** CRITICAL
- **文件位置:** `src\transformers\models\bloom\convert_bloom_original_checkpoint_to_pytorch.py:167`
- **数据流:** 用户通过命令行参数 --bloom_checkpoint_path 传入路径 -> os.listdir() 列出目录文件 -> 文件名拼接后传入 torch.load()
- **判断理由:** 与第107行相同的漏洞，在另一个代码分支中同样使用了不安全的 torch.load() 加载用户可控路径下的文件。攻击者可以通过控制 checkpoint 目录内容实现任意代码执行。

**代码片段:**
```
temp = torch.load(os.path.join(bloom_checkpoint_path, f_name), map_location="cpu")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-ACC8B17C - 不安全的PyTorch模型加载

- **严重等级:** HIGH
- **文件位置:** `src/transformers/models/chameleon/convert_chameleon_weights_to_hf.py:133`
- **数据流:** 用户通过--input_dir参数指定输入路径 -> 构建possible_path -> torch.load直接加载该路径下的.pth文件
- **判断理由:** torch.load()默认使用pickle反序列化，可以执行任意代码。攻击者如果能够控制输入目录或替换其中的.pth文件，可以构造恶意的pickle数据实现远程代码执行。虽然map_location='cpu'限制了设备映射，但无法防御pickle反序列化攻击。

**代码片段:**
```
loaded = torch.load(possible_path, map_location="cpu")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-046C6FF6 - 不安全的PyTorch模型加载

- **严重等级:** HIGH
- **文件位置:** `src/transformers/models/chameleon/convert_chameleon_weights_to_hf.py:139`
- **数据流:** 用户通过--input_dir参数指定输入路径 -> 构建input_model_path -> 循环加载consolidated.{i:02d}.pth文件
- **判断理由:** 与第133行相同的问题，使用torch.load加载多个分片文件，每个文件都可能包含恶意pickle数据。攻击者可以替换任意分片文件实现代码执行。

**代码片段:**
```
loaded = [torch.load(os.path.join(input_model_path, f"consolidated.{i:02d}.pth"), map_location="cpu") for i in range(num_shards)]
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-E97FF639 - 不安全的PyTorch模型加载

- **严重等级:** CRITICAL
- **文件位置:** `src\transformers\models\chinese_clip\convert_chinese_clip_original_pytorch_to_hf.py:107`
- **数据流:** 用户通过命令行参数--checkpoint_path传入checkpoint_path，该路径直接传递给torch.load()函数，未使用weights_only=True参数，可能加载包含恶意代码的pickle文件。
- **判断理由:** torch.load()默认使用pickle反序列化，可以执行任意代码。攻击者可以构造恶意的.pt或.pth文件，当用户加载该文件时执行恶意代码。bandit工具标记为B614漏洞。虽然map_location='cpu'限制了设备，但无法防止pickle代码执行。

**代码片段:**
```
pt_weights = torch.load(checkpoint_path, map_location="cpu")["state_dict"]
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-239BF5FE - 不安全的PyTorch模型加载

- **严重等级:** CRITICAL
- **文件位置:** `src/transformers/models/clvp/convert_clvp_to_hf.py:206`
- **数据流:** 用户通过命令行参数checkpoint_path指定模型路径 -> os.path.join拼接路径 -> torch.load加载模型文件
- **判断理由:** 与第204行相同，这是另一个torch.load调用，同样存在pickle反序列化漏洞。攻击者可以构造恶意模型文件实现任意代码执行。

**代码片段:**
```
torch.load(each_model_path)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-5E9EB1BB - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `src\transformers\models\cvt\convert_cvt_original_pytorch_checkpoint_to_pytorch.py:287`
- **数据流:** hf_hub_download() is called without specifying a revision parameter, which means it will download the latest version of the model from the Hugging Face Hub. This could lead to downloading a malicious or compromised version if the repository is compromised.
- **判断理由:** The function hf_hub_download() is imported but not shown in the provided code snippet. However, based on the bandit warning, it is used without a revision pin. Without pinning a specific revision (commit hash or tag), the download is vulnerable to supply chain attacks where an attacker could compromise the repository and replace the model with a malicious one.

**代码片段:**
```
from huggingface_hub import hf_hub_download
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-89C693B6 - 不安全的PyTorch模型加载

- **严重等级:** CRITICAL
- **文件位置:** `src\transformers\models\data2vec\convert_data2vec_vision_original_pytorch_checkpoint_to_pytorch.py:227`
- **数据流:** 用户通过命令行参数 --beit_checkpoint 指定检查点路径 -> 加载到state_dict -> 直接用于模型加载
- **判断理由:** 代码使用torch.load()加载用户指定的检查点文件，但未对加载的pickle数据进行任何安全验证。PyTorch的torch.load()基于pickle模块，可以执行任意代码。攻击者可以通过提供恶意的.pt或.pth文件实现远程代码执行。

**代码片段:**
```
def load_beit_model(args, is_finetuned, is_large):
    def load_state_dict(model, state_dict, prefix="", ignore_missing="relative_position_index"):
        ...
        state_dict = state_dict.copy()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-97D55A69 - 不安全的PyTorch模型加载

- **严重等级:** CRITICAL
- **文件位置:** `src\transformers\models\deprecated\mega\convert_mega_original_pytorch_checkpoint_to_pytorch.py:135`
- **数据流:** 用户通过命令行参数pretrained_checkpoint_path指定路径 → 拼接路径加载.pt文件 → torch.load()反序列化
- **判断理由:** torch.load()默认使用pickle反序列化，可以执行任意代码。攻击者可以通过提供恶意的.pt文件实现远程代码执行。虽然设置了map_location='cpu'，但这不影响反序列化的安全性。

**代码片段:**
```
torch.load(os.path.join(pretrained_checkpoint_path, "encoder_weights.pt"), map_location="cpu")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-253B32AA - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `src/transformers/models/deprecated/realm/retrieval_realm.py:114`
- **数据流:** 用户通过pretrained_model_name_or_path参数传入模型名称或路径，该参数直接传递给hf_hub_download函数，未指定revision参数，导致可能下载到恶意或未预期的版本。
- **判断理由:** hf_hub_download函数未指定revision参数（如commit hash或tag），默认可能下载最新版本，存在供应链攻击风险。攻击者若控制仓库或提交恶意更新，可能导致用户下载恶意文件。

**代码片段:**
```
block_records_path = hf_hub_download(
    repo_id=pretrained_model_name_or_path, filename=_REALM_BLOCK_RECORDS_FILENAME, **kwargs
)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-2E4096F0 - Unsafe deserialization via numpy.load with allow_pickle=True

- **严重等级:** HIGH
- **文件位置:** `src/transformers/models/deprecated/realm/retrieval_realm.py:116`
- **数据流:** 从hf_hub_download下载的文件路径或本地路径传递给np.load，allow_pickle=True允许加载pickle数据，可能执行任意代码。
- **判断理由:** numpy.load默认allow_pickle=False，但此处显式设置为True。pickle反序列化可执行任意Python代码，若攻击者控制block_records.npy文件，可导致远程代码执行。结合未固定revision的下载，风险更高。

**代码片段:**
```
block_records = np.load(block_records_path, allow_pickle=True)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-08AE7401 - 不安全的反序列化 - pickle.load

- **严重等级:** CRITICAL
- **文件位置:** `src\transformers\models\deprecated\transfo_xl\tokenization_transfo_xl.py:213`
- **数据流:** 用户通过pretrained_vocab_file参数传入文件路径 -> 代码检查TRUST_REMOTE_CODE环境变量 -> 如果设置为True则允许后续的pickle.load操作 -> 反序列化可能包含恶意payload的pickle文件
- **判断理由:** 代码虽然添加了TRUST_REMOTE_CODE环境变量检查，但该检查仅通过环境变量控制，用户可能被诱导设置该环境变量。一旦设置，后续的pickle.load()将直接反序列化用户提供的文件，可能导致任意代码执行。这是一个严重的安全漏洞，因为pickle反序列化可以执行任意Python代码。

**代码片段:**
```
if pretrained_vocab_file is not None:
    # Priority on pickle files (support PyTorch and TF)
    if not strtobool(os.environ.get("TRUST_REMOTE_CODE", "False")):
        raise ValueError(
            "This part uses `pickle.load` which is insecure and will execute arbitrary code that is "
            "potentially malicious. It's recommended to never unpickle data that could have come from an "
            "untrusted source, or that could have been tampered with. If you already verified the pickle "
            "data and decided to use it, you can set the environment variable "
            "`TRUST_REMOTE_CODE` to `True` to allow it."
        )
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-7FD270F9 - 不安全的反序列化 - PyTorch load

- **严重等级:** CRITICAL
- **文件位置:** `src\transformers\models\deprecated\transfo_xl\tokenization_transfo_xl.py:225`
- **数据流:** 用户提供pretrained_vocab_file_torch参数 -> 代码使用torch.load()加载文件 -> 反序列化可能包含恶意payload的PyTorch模型文件
- **判断理由:** PyTorch的torch.load()默认使用pickle进行反序列化，可以执行任意代码。如果用户加载了来自不可信来源的模型文件，可能导致任意代码执行。

**代码片段:**
```
[B614] Use of unsafe PyTorch load
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-C98D0AF2 - 不安全的反序列化 - pickle.load

- **严重等级:** CRITICAL
- **文件位置:** `src\transformers\models\deprecated\transfo_xl\tokenization_transfo_xl.py:798`
- **数据流:** 代码加载pickle格式的词汇表文件 -> 使用pickle.load()反序列化 -> 可能执行恶意代码
- **判断理由:** 直接使用pickle.load()反序列化词汇表文件，如果文件来自不可信来源或被篡改，可能导致任意代码执行。这是最经典的pickle反序列化漏洞场景。

**代码片段:**
```
[B301] Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-6F00E90E - 不安全的反序列化（PyTorch load）

- **严重等级:** CRITICAL
- **文件位置:** `src\transformers\models\dialogpt\convert_dialogpt_original_pytorch_checkpoint_to_pytorch.py:30`
- **数据流:** 用户通过命令行参数 --dialogpt_path 指定路径，该路径与模型名称拼接后形成 checkpoint_path，然后直接传入 torch.load() 进行反序列化。
- **判断理由:** torch.load() 默认使用 pickle 模块进行反序列化，而 pickle 在加载恶意构造的数据时可能执行任意代码。攻击者可以通过控制 --dialogpt_path 参数指向一个恶意文件，导致代码执行。虽然该脚本主要用于模型转换，但若在自动化流程中暴露给用户输入，则存在严重安全风险。建议使用 torch.load(..., map_location='cpu', weights_only=True) 或验证文件来源。

**代码片段:**
```
d = torch.load(checkpoint_path)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-9552C00E - 不安全的反序列化 - PyTorch模型加载

- **严重等级:** CRITICAL
- **文件位置:** `src/transformers/models/fastspeech2_conformer/convert_hifigan.py:107`
- **数据流:** 用户通过命令行参数 --checkpoint_path 传入checkpoint_path -> 直接传递给torch.load() -> 反序列化执行任意代码
- **判断理由:** torch.load()默认使用pickle反序列化，可以执行任意代码。攻击者可以构造恶意的.pt或.pth文件，当用户加载该文件时，会在目标机器上执行任意Python代码。checkpoint_path来自命令行参数，用户可控，存在严重的安全风险。

**代码片段:**
```
orig_checkpoint = torch.load(checkpoint_path)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-5EFF1B2A - 不安全的序列化状态恢复

- **严重等级:** HIGH
- **文件位置:** `src/transformers/models/fastspeech2_conformer/tokenization_fastspeech2_conformer.py:130`
- **数据流:** 反序列化时d参数直接赋值给self.__dict__ -> 恢复对象状态
- **判断理由:** __setstate__方法直接将反序列化的字典赋值给__dict__，没有进行任何校验。攻击者可以构造恶意的pickle数据，在反序列化时恢复任意属性值，包括可能被滥用的回调函数或恶意对象。虽然g2p属性被重新初始化，但其他属性（如encoder、decoder）可能被篡改。

**代码片段:**
```
def __setstate__(self, d):
    self.__dict__ = d
    try:
        import g2p_en
        self.g2p = g2p_en.G2p()
    except ImportError:
        raise ImportError(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-F609E5AA - 不安全的PyTorch模型加载（远程URL）

- **严重等级:** HIGH
- **文件位置:** `src\transformers\models\flava\convert_flava_original_pytorch_to_hf.py:69`
- **数据流:** 用户通过命令行参数--checkpoint_path传入checkpoint_path -> 函数convert_flava_checkpoint接收该参数 -> 当本地文件不存在时，在line 69直接传递给torch.hub.load_state_dict_from_url()
- **判断理由:** torch.hub.load_state_dict_from_url()会从任意URL下载并加载PyTorch模型，同样使用pickle反序列化。攻击者可以提供一个指向恶意文件的URL，导致任意代码执行。该函数没有对URL来源进行白名单验证，也没有固定版本或哈希值。

**代码片段:**
```
state_dict = torch.hub.load_state_dict_from_url(checkpoint_path, map_location="cpu")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-89F40906 - 不安全的反序列化 - PyTorch模型加载

- **严重等级:** CRITICAL
- **文件位置:** `src/transformers/models/gemma2/convert_gemma2_weights_to_hf.py:100`
- **数据流:** 用户通过命令行参数 --input_checkpoint 指定输入路径 -> input_base_path 变量 -> os.path.join(input_base_path, file) 构建文件路径 -> torch.load() 加载文件内容
- **判断理由:** torch.load() 默认使用 pickle 反序列化，可以执行任意代码。攻击者可以通过提供恶意的 .bin 文件或控制 input_base_path 参数指向恶意文件，在模型加载过程中执行任意Python代码。虽然 map_location='cpu' 限制了设备映射，但无法防止pickle反序列化攻击。

**代码片段:**
```
loaded_state_dict = torch.load(os.path.join(input_base_path, file), map_location="cpu")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-C69BE11E - 不安全的反序列化 - PyTorch模型加载

- **严重等级:** CRITICAL
- **文件位置:** `src/transformers/models/gemma2/convert_gemma2_weights_to_hf.py:104`
- **数据流:** 用户通过命令行参数 --input_checkpoint 指定输入路径 -> input_base_path 变量直接传递给 torch.load() -> 加载文件内容并访问 'model_state_dict' 键
- **判断理由:** 与第100行相同的反序列化漏洞。当输入路径指向单个文件（非目录）时，直接使用 torch.load() 加载用户指定的文件。攻击者可以构造恶意的pickle文件，在反序列化过程中执行任意代码。

**代码片段:**
```
model_state_dict = torch.load(input_base_path, map_location="cpu")["model_state_dict"]
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-4FDF2964 - 不安全的反序列化 - PyTorch模型加载

- **严重等级:** CRITICAL
- **文件位置:** `src\transformers\models\gpt_sw3\convert_megatron_to_pytorch.py:156`
- **数据流:** 用户通过命令行参数--checkpoint_path传入文件路径 -> 直接传递给torch.load()进行反序列化
- **判断理由:** torch.load()默认使用pickle进行反序列化，可以执行任意代码。攻击者可以构造恶意的pickle文件，当模型加载时执行任意Python代码。虽然map_location='cpu'限制了设备映射，但无法防止pickle反序列化攻击。checkpoint_path来自用户输入，攻击者可以控制加载的文件路径。

**代码片段:**
```
checkpoint = torch.load(checkpoint_path, map_location="cpu")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-E02F3E0A - 代码注入

- **严重等级:** CRITICAL
- **文件位置:** `src\transformers\models\hubert\convert_distilhubert_original_s3prl_checkpoint_to_pytorch.py:164`
- **数据流:** 用户输入通过模型配置文件(fs_config.extractor_conv_feature_layers)传入，该值可能来自外部来源（如下载的模型配置），然后直接传递给eval()函数执行。
- **判断理由:** eval()函数会执行任意Python代码。fs_config.extractor_conv_feature_layers的值来自模型配置，如果攻击者能够控制或篡改该配置（例如通过恶意模型文件），则可以注入任意代码。bandit工具已标记此行为B307。建议使用ast.literal_eval()替代，它只解析字面量表达式，更安全。

**代码片段:**
```
conv_layers = eval(fs_config.extractor_conv_feature_layers)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-1ED3B73F - 命令注入

- **严重等级:** HIGH
- **文件位置:** `src/transformers/models/layoutlmv2/image_processing_layoutlmv2.py:56`
- **数据流:** 用户可控的tesseract_config参数通过__init__或preprocess方法传入 -> apply_tesseract函数 -> 直接传递给pytesseract.image_to_data的config参数
- **判断理由:** tesseract_config参数直接传递给pytesseract的config参数，而pytesseract底层调用Tesseract OCR引擎时，config参数会被作为命令行参数传递给tesseract进程。攻击者可以通过注入特殊字符（如分号、管道符等）执行任意系统命令。虽然pytesseract库本身可能有一些过滤，但直接传递用户输入到命令行参数仍然存在命令注入风险。

**代码片段:**
```
tesseract_config = tesseract_config if tesseract_config is not None else ""
...
data = pytesseract.image_to_data(pil_image, lang=lang, output_type="dict", config=tesseract_config)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-C65CC777 - 不安全的PyTorch模型加载

- **严重等级:** HIGH
- **文件位置:** `src/transformers/models/llava/convert_llava_weights_to_hf.py:144`
- **数据流:** 用户通过命令行参数 --old_state_dict_id 指定模型ID，该ID用于从Hugging Face Hub下载模型文件（model_state_dict.bin），然后通过torch.load()加载该文件。攻击者可以上传恶意模型文件到Hub，诱导用户使用恶意ID，导致任意代码执行。
- **判断理由:** torch.load()默认使用pickle反序列化，可以执行任意代码。虽然map_location='cpu'限制了设备，但无法防止pickle反序列化攻击。攻击者可以构造恶意的.pt/.bin文件，在加载时执行恶意代码。

**代码片段:**
```
state_dict = torch.load(state_dict_path, map_location="cpu")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-45C904DF - 不安全的Hugging Face Hub下载（无版本锁定）

- **严重等级:** MEDIUM
- **文件位置:** `src/transformers/models/llava/convert_llava_weights_to_hf.py:143`
- **数据流:** 用户通过命令行参数 --old_state_dict_id 传入模型ID，该参数直接传递给hf_hub_download()，未指定revision参数。
- **判断理由:** hf_hub_download()未指定revision参数，会下载仓库的最新版本。如果仓库被恶意更新，可能导致下载恶意模型文件。

**代码片段:**
```
state_dict_path = hf_hub_download(old_state_dict_id, "model_state_dict.bin")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-AC5BF00E - 不安全的PyTorch模型加载

- **严重等级:** HIGH
- **文件位置:** `src\transformers\models\longformer\convert_longformer_original_pytorch_lightning_to_pytorch.py:45`
- **数据流:** 用户通过命令行参数 --longformer_question_answering_ckpt_path 传入路径 -> args.longformer_question_answering_ckpt_path -> convert_longformer_qa_checkpoint_to_pytorch 函数参数 -> torch.load() 直接加载
- **判断理由:** torch.load() 默认使用 pickle 反序列化，可以执行任意代码。攻击者可以提供一个恶意的 .ckpt 文件，在加载时执行恶意负载。虽然 map_location 限制了设备，但无法防止 pickle 代码执行。

**代码片段:**
```
ckpt = torch.load(longformer_question_answering_ckpt_path, map_location=torch.device("cpu"))
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-161B65E7 - 不安全的PyTorch模型加载

- **严重等级:** HIGH
- **文件位置:** `src\transformers\models\luke\convert_luke_original_pytorch_checkpoint_to_pytorch.py:35`
- **数据流:** 用户通过命令行参数 --checkpoint_path 传入 checkpoint_path -> 直接传递给 torch.load() 进行反序列化
- **判断理由:** torch.load() 默认使用 pickle 模块反序列化，可以执行任意代码。攻击者可以构造恶意的 .bin 文件，在加载时执行恶意负载。虽然 map_location='cpu' 限制了设备，但无法防止 pickle 代码执行。

**代码片段:**
```
state_dict = torch.load(checkpoint_path, map_location="cpu")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-8E3FC217 - 不安全的反序列化

- **严重等级:** CRITICAL
- **文件位置:** `src/transformers/models/mamba/convert_mamba_ssm_checkpoint_to_pytorch.py:111`
- **数据流:** 用户通过命令行参数 --mamba_checkpoint_file 提供文件路径 -> 传递给 convert_mamba_checkpoint_file_to_huggingface_model_file 函数 -> 直接作为 torch.load() 的参数加载
- **判断理由:** torch.load() 默认使用 pickle 模块反序列化数据，可以执行任意代码。攻击者可以构造恶意的 .bin 文件，当用户加载该文件时，会在目标系统上执行任意代码。虽然 map_location 参数限制了设备映射，但无法阻止 pickle 的代码执行攻击。这是一个严重的安全漏洞，因为用户输入直接控制文件路径，且 torch.load 本身是不安全的。

**代码片段:**
```
original_state_dict = torch.load(mamba_checkpoint_path, map_location="cpu")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-502820DE - 不安全的文件操作

- **严重等级:** MEDIUM
- **文件位置:** `src/transformers/models/marian/tokenization_marian.py:91`
- **数据流:** pad_token 参数通过 __init__ 方法传入 -> 用于字典键检查
- **判断理由:** 使用 assert 进行字典键存在性检查是不安全的，因为 assert 在 Python 优化模式下会被禁用。应该使用 if str(pad_token) not in self.encoder: raise KeyError(...) 替代。

**代码片段:**
```
assert str(pad_token) in self.encoder
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B0CA37A3 - 不安全的反序列化 - PyTorch模型加载

- **严重等级:** HIGH
- **文件位置:** `src/transformers/models/megatron_bert/convert_megatron_bert_checkpoint.py:297`
- **数据流:** 用户提供的checkpoint文件路径 -> torch.load() -> 反序列化执行任意代码
- **判断理由:** torch.load()默认使用pickle进行反序列化，可以执行任意代码。攻击者可以构造恶意的checkpoint文件，在加载时执行任意Python代码。该函数没有使用weights_only=True参数来限制反序列化的内容。

**代码片段:**
```
torch.load(input_state_dict)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-96A7CFA9 - 不安全的反序列化 - PyTorch模型加载

- **严重等级:** HIGH
- **文件位置:** `src/transformers/models/megatron_bert/convert_megatron_bert_checkpoint.py:299`
- **数据流:** 用户提供的checkpoint文件路径 -> torch.load() -> 反序列化执行任意代码
- **判断理由:** 与第297行相同的漏洞，torch.load()默认使用pickle反序列化，存在代码执行风险。攻击者可以构造恶意pickle数据，在模型加载时执行任意系统命令。

**代码片段:**
```
torch.load(input_state_dict)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-3386639A - 不安全的PyTorch模型加载

- **严重等级:** CRITICAL
- **文件位置:** `src/transformers/models/megatron_gpt2/checkpoint_reshaping_and_interoperability.py:275`
- **数据流:** 用户通过命令行参数--load_path指定加载路径，该路径被直接传递给torch.load()函数，未对加载的pickle数据进行任何安全校验
- **判断理由:** torch.load()默认使用pickle模块反序列化数据，可以执行任意代码。攻击者可以构造恶意的.pt或.pth文件，当用户加载该文件时执行恶意代码。Bandit工具标记为B614漏洞。

**代码片段:**
```
torch.load(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-C3ABA65F - 不安全的PyTorch模型加载

- **严重等级:** CRITICAL
- **文件位置:** `src/transformers/models/megatron_gpt2/checkpoint_reshaping_and_interoperability.py:298`
- **数据流:** 用户通过命令行参数--load_path指定加载路径，该路径被直接传递给torch.load()函数，未对加载的pickle数据进行任何安全校验
- **判断理由:** 与第275行相同的漏洞，torch.load()默认使用pickle反序列化，存在代码执行风险。Bandit工具标记为B614漏洞。

**代码片段:**
```
torch.load(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-22BE2475 - 不安全的PyTorch模型加载

- **严重等级:** CRITICAL
- **文件位置:** `src/transformers/models/megatron_gpt2/checkpoint_reshaping_and_interoperability.py:338`
- **数据流:** 用户通过命令行参数--load_path指定加载路径，该路径被直接传递给torch.load()函数，未对加载的pickle数据进行任何安全校验
- **判断理由:** 与第275行相同的漏洞，torch.load()默认使用pickle反序列化，存在代码执行风险。Bandit工具标记为B614漏洞。

**代码片段:**
```
torch.load(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-3898811F - 不安全的PyTorch模型加载

- **严重等级:** CRITICAL
- **文件位置:** `src/transformers/models/megatron_gpt2/checkpoint_reshaping_and_interoperability.py:619`
- **数据流:** 用户通过命令行参数--load_path指定加载路径，该路径被直接传递给torch.load()函数，未对加载的pickle数据进行任何安全校验
- **判断理由:** 与第275行相同的漏洞，torch.load()默认使用pickle反序列化，存在代码执行风险。Bandit工具标记为B614漏洞。

**代码片段:**
```
torch.load(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-E8259AB2 - 不安全的Hugging Face Hub下载（未固定版本）

- **严重等级:** HIGH
- **文件位置:** `src/transformers/models/megatron_gpt2/checkpoint_reshaping_and_interoperability.py:557`
- **数据流:** 用户通过命令行参数--tokenizer_name指定模型名称，该名称被传递给from_pretrained()方法，未指定revision参数固定版本
- **判断理由:** from_pretrained()方法从Hugging Face Hub下载模型时，如果未指定revision参数，将默认下载最新版本。攻击者可以上传恶意版本到Hub，导致用户下载并加载恶意模型。Bandit工具标记为B615漏洞。

**代码片段:**
```
from_pretrained()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-0DBB1C85 - 不安全的PyTorch模型加载

- **严重等级:** CRITICAL
- **文件位置:** `src/transformers/models/megatron_gpt2/convert_megatron_gpt2_checkpoint.py:266`
- **数据流:** 用户通过命令行参数args.input_checkpoint指定检查点文件路径 -> torch.load()直接加载该文件，未进行任何安全校验
- **判断理由:** torch.load()默认使用pickle反序列化，可以执行任意代码。攻击者可以构造恶意的.pt/.pth文件，当用户加载该文件时，会在目标机器上执行任意Python代码。这是严重的安全漏洞，可能导致完全的系统入侵。

**代码片段:**
```
input_state_dict = torch.load(args.input_checkpoint, map_location='cpu')
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-45AA0C48 - 不安全的PyTorch模型加载

- **严重等级:** CRITICAL
- **文件位置:** `src/transformers/models/megatron_gpt2/convert_megatron_gpt2_checkpoint.py:268`
- **数据流:** 与第266行相同，用户输入直接传递给torch.load()
- **判断理由:** 与第266行相同的漏洞，torch.load()使用pickle反序列化，存在代码执行风险。

**代码片段:**
```
input_state_dict = torch.load(args.input_checkpoint, map_location='cpu')
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-4EDBE4E2 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `src/transformers/models/mgp_str/processing_mgp_str.py:74`
- **数据流:** AutoTokenizer.from_pretrained() downloads model from Hugging Face Hub without specifying a revision/hash, potentially loading untrusted or malicious model versions.
- **判断理由:** Bandit B615: Using from_pretrained() without a revision parameter means the code will always download the latest version of the model. If the model repository is compromised or a malicious update is pushed, the application could load a tampered tokenizer with embedded malicious code. This is a supply chain security risk.

**代码片段:**
```
self.bpe_tokenizer = AutoTokenizer.from_pretrained("openai-community/gpt2")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-CB48D18E - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `src/transformers/models/mgp_str/processing_mgp_str.py:75`
- **数据流:** AutoTokenizer.from_pretrained() downloads model from Hugging Face Hub without specifying a revision/hash, potentially loading untrusted or malicious model versions.
- **判断理由:** Bandit B615: Same vulnerability as line 74. The from_pretrained() call for the BERT tokenizer also lacks revision pinning, making it susceptible to supply chain attacks if the upstream repository is compromised.

**代码片段:**
```
self.wp_tokenizer = AutoTokenizer.from_pretrained("google-bert/bert-base-uncased")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-DA0418F2 - 不安全的PyTorch模型加载

- **严重等级:** HIGH
- **文件位置:** `src/transformers/models/mistral/convert_mistral_weights_to_hf.py:132`
- **数据流:** 用户通过命令行参数--input_dir指定input_base_path，该路径直接传递给torch.load()加载.pth文件。攻击者可以构造恶意的.pth文件，利用PyTorch的pickle反序列化机制执行任意代码。
- **判断理由:** torch.load()默认使用pickle模块进行反序列化，pickle在加载数据时会执行嵌入的任意Python代码。虽然map_location='cpu'限制了设备，但无法防止恶意pickle数据执行代码。攻击者如果能够控制input_base_path指向的目录，可以放置恶意.pth文件，导致代码执行。

**代码片段:**
```
loaded = [
    torch.load(os.path.join(input_base_path, f"consolidated.{i:02d}.pth"), map_location="cpu")
    for i in range(num_shards)
]
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-FDC97960 - 不安全的PyTorch模型加载

- **严重等级:** HIGH
- **文件位置:** `src/transformers/models/mixtral/convert_mixtral_weights_to_hf.py:97`
- **数据流:** 用户通过命令行参数--input_dir指定input_base_path -> 该路径被用于os.path.join构造文件路径 -> torch.load加载该路径下的.pt文件
- **判断理由:** torch.load()默认使用pickle模块反序列化数据，而pickle反序列化可以执行任意代码。如果攻击者能够控制input_base_path指向的目录或其中的.pt文件，就可以通过构造恶意的pickle数据实现远程代码执行。虽然map_location='cpu'限制了设备映射，但无法防御pickle本身的代码执行攻击。

**代码片段:**
```
loaded = [
    torch.load(os.path.join(input_base_path, f"consolidated.{i:02d}.pt"), map_location="cpu") for i in range(8)
]
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-2162CA40 - 不安全的PyTorch模型加载

- **严重等级:** HIGH
- **文件位置:** `src\transformers\models\mra\convert_mra_pytorch_to_pytorch.py:80`
- **数据流:** 用户通过命令行参数 --pytorch_model_path 传入 checkpoint_path -> torch.load() 直接加载该路径的模型文件，未进行任何校验或安全处理
- **判断理由:** torch.load() 默认使用 pickle 反序列化，可以执行任意代码。攻击者可以构造恶意的 .pt 或 .pth 文件，当用户加载该文件时，会在目标机器上执行任意代码。虽然该脚本是转换工具，但用户可能从不可信来源下载模型文件，存在严重安全风险。建议使用 weights_only=True 参数或使用 safetensors 格式。

**代码片段:**
```
orig_state_dict = torch.load(checkpoint_path, map_location="cpu")["model_state_dict"]
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-696F5B41 - 不安全的反序列化 - PyTorch模型加载

- **严重等级:** CRITICAL
- **文件位置:** `src/transformers/models/olmo/convert_olmo_weights_to_hf.py:94`
- **数据流:** 用户通过命令行参数--input_dir指定input_base_path -> os.path.join构造文件路径 -> torch.load()加载模型文件，该函数使用pickle反序列化
- **判断理由:** torch.load()底层使用pickle进行反序列化，如果加载的模型文件被恶意篡改，可能导致任意代码执行。攻击者可以构造恶意的.pt文件，在反序列化时执行任意Python代码。虽然map_location='cpu'限制了设备，但无法防止pickle反序列化攻击。

**代码片段:**
```
loaded = torch.load(os.path.join(input_base_path, "model.pt"), map_location="cpu")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-2461BFD2 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `src/transformers/models/oneformer/convert_to_hf_oneformer.py:230`
- **数据流:** from_pretrained()调用未指定revision参数 -> 从Hugging Face Hub下载模型配置
- **判断理由:** from_pretrained()调用没有指定revision参数，会默认下载最新版本。如果模型仓库被恶意更新，可能导致下载恶意模型，造成供应链攻击。

**代码片段:**
```
（代码片段未完整显示，但根据bandit报告，该行存在from_pretrained()调用未指定revision）
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-04AA3782 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `src/transformers/models/oneformer/image_processing_oneformer.py:365`
- **数据流:** The import statement at line 365 imports hf_hub_download function. The actual vulnerable calls would be at lines where hf_hub_download() is invoked without specifying a revision parameter.
- **判断理由:** The bandit static analysis tool flagged B615 vulnerability at lines 365 and 367. The import of hf_hub_download from huggingface_hub without revision pinning means that when this function is called elsewhere in the code, it may download model files without specifying a specific commit hash or tag. This could lead to supply chain attacks where a malicious actor could update the repository with compromised files, and the code would automatically download the latest version without verification.

**代码片段:**
```
from huggingface_hub import hf_hub_download
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-D718E3F5 - 不安全的反序列化 (PyTorch load)

- **严重等级:** CRITICAL
- **文件位置:** `src\transformers\models\opt\convert_opt_original_pytorch_checkpoint_to_pytorch.py:32`
- **数据流:** 用户通过命令行参数 --fairseq_path 传入 checkpoint_path -> 传递给 load_checkpoint 函数 -> 在 line 32 直接调用 torch.load 加载该路径文件
- **判断理由:** torch.load 默认使用 pickle 反序列化，可以执行任意代码。攻击者可以构造恶意的 .pt 文件，通过 --fairseq_path 参数传入，导致远程代码执行。虽然 map_location 参数限制了设备映射，但不影响 pickle 反序列化的安全性。

**代码片段:**
```
sd = torch.load(checkpoint_path, map_location="cpu")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-BE63070E - 不安全的反序列化 - PyTorch模型加载

- **严重等级:** CRITICAL
- **文件位置:** `src\transformers\models\persimmon\convert_persimmon_weights_to_hf.py:85`
- **数据流:** 用户通过命令行参数 --pt_model_path 传入文件路径 -> args.pt_model_path -> convert_persimmon_checkpoint函数的pt_model_path参数 -> torch.load(pt_model_path)
- **判断理由:** torch.load()默认使用pickle反序列化，可以执行任意代码。攻击者可以构造恶意的.pt文件，当用户加载该文件时，会在目标系统上执行任意代码。虽然map_location参数限制了设备映射，但无法防止pickle反序列化攻击。这是一个严重的安全漏洞，因为模型文件通常来自不可信的第三方来源。

**代码片段:**
```
model_state_dict_base = torch.load(pt_model_path, map_location="cpu")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-39B99CDD - 不安全的临时文件/路径操作

- **严重等级:** MEDIUM
- **文件位置:** `src\transformers\models\persimmon\convert_persimmon_weights_to_hf.py:85`
- **数据流:** 用户通过命令行参数 --ada_lib_path 传入路径 -> args.ada_lib_path -> sys.path.insert(0, ada_lib_path)
- **判断理由:** ada_lib_path参数直接来自用户输入，被插入到Python模块搜索路径的最前面。攻击者可以指定一个包含恶意Python模块的目录，导致后续的import语句加载恶意代码。这相当于代码注入漏洞。

**代码片段:**
```
sys.path.insert(0, ada_lib_path)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-1C1B6383 - 不安全的反序列化 (Pickle)

- **严重等级:** CRITICAL
- **文件位置:** `src\transformers\models\rag\retrieval_rag.py:158`
- **数据流:** 用户可控的index_path参数 -> _resolve_path() -> cached_file() -> 返回文件路径 -> _deserialize_index() -> open() -> pickle.load()
- **判断理由:** 与第142行相同的pickle反序列化漏洞。代码从index_path加载元数据文件并使用pickle.load()反序列化。同样受TRUST_REMOTE_CODE环境变量控制，但一旦该变量被设置为True，攻击者可以通过提供恶意的元数据文件实现任意代码执行。这是典型的pickle反序列化远程代码执行漏洞。

**代码片段:**
```
with open(resolved_meta_path, "rb") as metadata_file:
    self.index_id_to_db_id = pickle.load(metadata_file)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-8AA2FD93 - 不安全的反序列化 - PyTorch模型加载

- **严重等级:** CRITICAL
- **文件位置:** `src/transformers/models/recurrent_gemma/convert_recurrent_gemma_to_hf.py:74`
- **数据流:** 用户通过命令行参数 --input_checkpoint 提供文件路径 -> args.input_checkpoint -> write_model()函数的input_base_path参数 -> torch.load(input_base_path)直接加载该路径指向的pickle文件
- **判断理由:** torch.load()底层使用Python的pickle模块进行反序列化，pickle在反序列化过程中可以执行任意代码。攻击者可以构造恶意的.pt文件，当用户加载该文件时，会在目标机器上执行任意恶意代码。虽然该脚本是转换工具，但input_checkpoint参数直接来自用户输入，没有对文件来源和内容进行任何校验，存在严重的安全风险。

**代码片段:**
```
model_state_dict = torch.load(input_base_path, map_location="cpu")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-6C8BDA0A - 不安全的反序列化

- **严重等级:** HIGH
- **文件位置:** `src\transformers\models\reformer\convert_reformer_trax_checkpoint_to_pytorch.py:192`
- **数据流:** 用户通过命令行参数 --trax_model_pkl_path 提供文件路径 -> 传递给 convert_trax_checkpoint_to_pytorch 函数 -> 在 line 192 使用 pickle.load 反序列化该文件内容
- **判断理由:** 代码使用 pickle.load() 反序列化用户指定的文件（trax_model_pkl_path），该路径来自命令行参数，可能被攻击者控制。pickle 反序列化可以执行任意代码，当加载恶意构造的 pickle 文件时，可能导致远程代码执行。虽然该脚本是转换工具，通常由开发者使用，但若攻击者能控制输入文件路径或替换文件，则存在严重安全风险。

**代码片段:**
```
with open(trax_model_pkl_path, "rb") as f:
    model_weights = pickle.load(f)["weights"]
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-22AAC7DF - 不安全的PyTorch模型加载

- **严重等级:** HIGH
- **文件位置:** `src\transformers\models\roberta_prelayernorm\convert_roberta_prelayernorm_original_pytorch_checkpoint_to_pytorch.py:40`
- **数据流:** 用户通过命令行参数--checkpoint-repo传入checkpoint_repo -> 传递给hf_hub_download下载模型文件 -> torch.load加载模型文件
- **判断理由:** torch.load()默认使用pickle反序列化，可以执行任意代码。攻击者可以上传恶意的PyTorch模型文件到Hugging Face Hub，当用户下载并加载该模型时，恶意代码会被执行。虽然模型来自Hugging Face Hub，但用户指定的仓库可能被篡改或包含恶意内容。

**代码片段:**
```
original_state_dict = torch.load(hf_hub_download(repo_id=checkpoint_repo, filename="pytorch_model.bin"))
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-E8701C4C - 代码注入 - eval()使用

- **严重等级:** CRITICAL
- **文件位置:** `src/transformers/models/sew/convert_sew_original_pytorch_checkpoint_to_pytorch.py:181`
- **数据流:** 用户输入或外部配置通过fs_config.conv_feature_layers传入，直接作为eval()的参数执行。fs_config可能来自加载的checkpoint文件，如果被恶意修改，可执行任意Python代码。
- **判断理由:** eval()函数会执行任意Python代码，而fs_config.conv_feature_layers的值来自外部加载的模型配置文件。如果攻击者能够控制该配置内容，就可以通过构造恶意的字符串来执行任意代码，导致远程代码执行(RCE)漏洞。应使用ast.literal_eval()替代，它只解析字面量表达式，更安全。

**代码片段:**
```
conv_layers = eval(fs_config.conv_feature_layers)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-7B1180D7 - 代码注入

- **严重等级:** CRITICAL
- **文件位置:** `src\transformers\models\sew_d\convert_sew_d_original_pytorch_checkpoint_to_pytorch.py:185`
- **数据流:** 用户提供的模型配置文件(fs_config.conv_feature_layers)通过eval()函数直接执行，攻击者可以构造恶意的配置文件内容导致任意代码执行。
- **判断理由:** eval()函数会执行任意Python代码，而fs_config.conv_feature_layers来源于外部模型配置文件，攻击者可以控制该配置内容，通过注入恶意代码实现远程代码执行。应使用ast.literal_eval()替代eval()来安全地解析Python字面量表达式。

**代码片段:**
```
conv_layers = eval(fs_config.conv_feature_layers)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-CBF67680 - 不安全的反序列化

- **严重等级:** CRITICAL
- **文件位置:** `src\transformers\models\speech_to_text\convert_s2t_fairseq_to_tfms.py:55`
- **数据流:** 用户通过命令行参数 --fairseq_path 传入 checkpoint_path，该路径直接传递给 torch.load() 函数进行反序列化。攻击者可以构造恶意的 .pt 文件，在反序列化时执行任意代码。
- **判断理由:** torch.load() 默认使用 pickle 模块进行反序列化，而 pickle 在反序列化过程中可以执行任意代码。用户提供的文件路径来自命令行参数，攻击者可以诱导用户加载恶意构造的模型文件，导致远程代码执行。这是已知的高危漏洞（CVE-2019-6446 等），bandit 工具也标记了此问题（B614）。

**代码片段:**
```
m2m_100 = torch.load(checkpoint_path, map_location="cpu")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-4CD6C674 - 不安全的PyTorch模型加载

- **严重等级:** HIGH
- **文件位置:** `src\transformers\models\univnet\convert_univnet.py:109`
- **数据流:** 用户通过命令行参数--checkpoint_path传入checkpoint_path -> 传递给convert_univnet_checkpoint函数 -> 直接作为torch.load()的参数
- **判断理由:** torch.load()默认使用pickle反序列化，可以执行任意代码。攻击者可以构造恶意的.pt或.pth文件，当用户加载该文件时，会在目标机器上执行任意代码。虽然map_location='cpu'限制了设备，但无法防止pickle反序列化攻击。

**代码片段:**
```
model_state_dict_base = torch.load(checkpoint_path, map_location="cpu")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-77886B0D - 不安全的PyTorch模型加载

- **严重等级:** CRITICAL
- **文件位置:** `src/transformers/models/video_llava/convert_video_llava_weights_to_hf.py:102`
- **数据流:** 用户通过命令行参数--old_state_dict_id指定模型ID -> hf_hub_download下载模型文件 -> torch.load加载模型文件
- **判断理由:** torch.load()默认使用pickle反序列化，可以执行任意代码。攻击者如果能够控制HuggingFace Hub上的模型文件，或者通过中间人攻击替换下载的文件，就可以在加载模型时执行任意恶意代码。虽然map_location='cpu'限制了设备映射，但无法防止pickle反序列化攻击。

**代码片段:**
```
state_dict = torch.load(state_dict_path, map_location="cpu")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-16871D23 - 不安全的PyTorch模型加载

- **严重等级:** HIGH
- **文件位置:** `src/transformers/models/vipllava/convert_vipllava_weights_to_hf.py:81`
- **数据流:** 用户通过命令行参数--old_state_dict_id指定模型ID -> hf_hub_download下载文件 -> torch.load加载文件
- **判断理由:** torch.load()默认使用pickle反序列化，可以执行任意代码。攻击者如果能够控制下载的模型文件（例如通过中间人攻击或上传恶意模型到Hugging Face Hub），可以在加载模型时执行任意Python代码。虽然map_location='cpu'限制了设备映射，但无法防止pickle反序列化攻击。

**代码片段:**
```
state_dict = torch.load(state_dict_path, map_location="cpu")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-C7EAB4E0 - 未固定版本的Hugging Face Hub下载

- **严重等级:** MEDIUM
- **文件位置:** `src/transformers/models/vipllava/convert_vipllava_weights_to_hf.py:79`
- **数据流:** 用户通过命令行参数--old_state_dict_id指定模型ID -> hf_hub_download下载状态字典文件
- **判断理由:** hf_hub_download()未指定revision参数，默认下载最新版本。攻击者可以上传恶意版本替换原始文件，导致下载恶意模型权重。

**代码片段:**
```
state_dict_path = hf_hub_download(old_state_dict_id, "model_state_dict_7b.bin")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-21876F40 - 不安全的PyTorch模型加载

- **严重等级:** HIGH
- **文件位置:** `src\transformers\models\yoso\convert_yoso_pytorch_to_pytorch.py:78`
- **数据流:** 用户通过命令行参数 --pytorch_model_path 传入 checkpoint_path -> 直接传递给 torch.load() 函数 -> 加载的模型状态字典被用于后续模型转换和保存
- **判断理由:** torch.load() 默认使用 pickle 模块反序列化数据，而 pickle 在反序列化时可能执行任意代码。攻击者可以构造恶意的 .bin 或 .pt 文件，当用户加载该文件时，会在目标系统上执行任意代码。虽然 map_location 参数限制了设备映射，但并未缓解 pickle 反序列化的根本风险。该函数接收用户提供的文件路径，且未对文件来源进行任何校验或限制，存在严重的安全隐患。

**代码片段:**
```
orig_state_dict = torch.load(checkpoint_path, map_location="cpu")["model_state_dict"]
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-D4639B1C - SSRF (Server-Side Request Forgery)

- **严重等级:** HIGH
- **文件位置:** `src\transformers\pipelines\audio_classification.py:152`
- **数据流:** 用户输入(inputs)作为URL直接传递给requests.get()，未进行任何URL验证或限制，攻击者可以控制请求的目标地址
- **判断理由:** 在preprocess方法中，当inputs是字符串且以http://或https://开头时，会直接使用requests.get()获取内容。攻击者可以传入恶意URL（如内网地址、云服务元数据端点等）来发起SSRF攻击。同时，requests.get()没有设置timeout参数，可能导致请求阻塞。

**代码片段:**
```
inputs = requests.get(inputs).content
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-64C59BB2 - 路径遍历

- **严重等级:** MEDIUM
- **文件位置:** `src\transformers\pipelines\audio_classification.py:153`
- **数据流:** 用户输入(inputs)作为文件路径直接传递给open()函数，未进行路径验证或限制
- **判断理由:** 当inputs是字符串且不以http://或https://开头时，会直接作为文件路径打开。攻击者可以通过传入路径遍历序列（如../../etc/passwd）来读取系统上的任意文件。

**代码片段:**
```
with open(inputs, "rb") as f:
    inputs = f.read()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-77B8EFC8 - SSRF/请求超时缺失

- **严重等级:** MEDIUM
- **文件位置:** `src\transformers\pipelines\automatic_speech_recognition.py:355`
- **数据流:** 代码中导入了requests库（第355行），但在整个文件中没有看到任何requests.get()或requests.post()调用。不过静态工具检测到第355行存在[B113]漏洞，表明在某个位置使用了requests调用但没有设置timeout参数。
- **判断理由:** Bandit静态分析工具检测到第355行存在B113漏洞，即调用requests库时没有设置timeout参数。这可能导致请求无限期阻塞，造成资源耗尽或服务不可用。虽然提供的代码片段中没有直接显示requests调用，但根据bandit报告，该文件中存在未设置超时的requests调用。

**代码片段:**
```
import requests

...

# 在类定义中使用了requests但没有设置timeout参数
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-C8B36E6B - 命令注入

- **严重等级:** CRITICAL
- **文件位置:** `src\transformers\pipelines\document_question_answering.py:67`
- **数据流:** 用户通过tesseract_config参数传入配置字符串 -> _sanitize_parameters方法接收tesseract_config参数 -> apply_tesseract函数将tesseract_config直接传递给pytesseract.image_to_data的config参数
- **判断理由:** tesseract_config参数直接传递给pytesseract的config参数，该参数会被传递给Tesseract OCR引擎的命令行。攻击者可以通过注入恶意命令（如使用shell命令分隔符）来执行任意系统命令。pytesseract在底层调用subprocess执行Tesseract命令时，config参数会被拼接到命令行中，导致命令注入漏洞。

**代码片段:**
```
data = pytesseract.image_to_data(image, lang=lang, output_type="dict", config=tesseract_config)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-26A0DB5D - SSRF (Server-Side Request Forgery)

- **严重等级:** HIGH
- **文件位置:** `src\transformers\pipelines\image_feature_extraction.py:60`
- **数据流:** 用户输入通过__call__方法传入，经过_sanitize_parameters处理timeout参数，然后传递给preprocess方法，最终调用load_image函数。用户可控制image参数（URL或本地路径）和timeout参数。
- **判断理由:** load_image函数接受用户提供的URL或本地路径作为输入，未对输入进行任何校验或白名单过滤。攻击者可以传入内网地址（如http://169.254.169.254/）或恶意服务器地址，导致SSRF攻击，可能泄露内部服务信息或进行端口扫描。

**代码片段:**
```
image = load_image(image, timeout=timeout)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-D101232B - SSRF (Server-Side Request Forgery)

- **严重等级:** HIGH
- **文件位置:** `src\transformers\pipelines\image_to_text.py:100`
- **数据流:** 用户输入通过__call__方法的images参数传入 -> preprocess方法接收image参数 -> 调用load_image(image, timeout=timeout) -> load_image函数会发起HTTP请求获取远程图片资源
- **判断理由:** load_image函数接受用户提供的URL（包括HTTP链接），并直接发起网络请求获取图片。攻击者可以传入恶意的内网URL（如http://localhost:8080/admin、http://169.254.169.254/latest/meta-data/等），导致SSRF攻击，可能访问内部网络资源或云服务元数据。虽然代码中提供了timeout参数，但这仅限制请求超时时间，并未对URL进行任何校验或白名单过滤。

**代码片段:**
```
image = load_image(image, timeout=timeout)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-496FA6EB - 路径遍历 (Path Traversal)

- **严重等级:** HIGH
- **文件位置:** `src\transformers\pipelines\image_to_text.py:100`
- **数据流:** 用户输入通过__call__方法的images参数传入 -> preprocess方法接收image参数 -> 调用load_image(image, timeout=timeout) -> load_image函数会尝试打开本地文件路径
- **判断理由:** load_image函数不仅支持HTTP URL，还支持本地文件路径。攻击者可以传入恶意的本地路径（如../../etc/passwd、/etc/shadow等），导致路径遍历漏洞，读取服务器上的任意文件。代码中没有对传入的路径进行任何校验或限制，也没有使用安全的路径拼接方式。

**代码片段:**
```
image = load_image(image, timeout=timeout)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-F8BAE11D - SSRF (Server-Side Request Forgery)

- **严重等级:** HIGH
- **文件位置:** `src\transformers\pipelines\object_detection.py:82`
- **数据流:** 用户通过__call__方法传入image参数 -> preprocess方法接收image参数 -> load_image函数直接处理用户提供的URL/路径
- **判断理由:** load_image函数接受用户输入的字符串作为参数，该字符串可以是HTTP(S)链接或本地文件路径。如果用户提供恶意的内网URL（如http://169.254.169.254/获取云元数据），服务器会发起请求，导致SSRF漏洞。虽然timeout参数可以设置超时，但没有对URL进行任何白名单或黑名单校验，攻击者可以探测内网服务。

**代码片段:**
```
def preprocess(self, image, timeout=None):
    image = load_image(image, timeout=timeout)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-3437AFD7 - SSRF (Server-Side Request Forgery) 和缺少超时设置

- **严重等级:** HIGH
- **文件位置:** `src/transformers/pipelines/video_classification.py:97`
- **数据流:** 用户输入(video参数) -> __call__方法 -> preprocess方法 -> requests.get(video) -> 发起HTTP请求
- **判断理由:** 1. 用户可以通过videos参数传入任意URL，包括http://或https://开头的链接。2. 代码直接使用requests.get()获取URL内容，没有对URL进行任何校验或白名单过滤，攻击者可以构造内网地址(如http://169.254.169.254/)获取云服务元数据。3. requests.get()没有设置timeout参数，可能导致请求长时间挂起，造成资源耗尽。4. 虽然代码检查了URL以http://或https://开头，但没有限制域名或IP范围，攻击者可以访问任意内部服务。

**代码片段:**
```
video = BytesIO(requests.get(video).content)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-44D1E1AF - SSRF (Server-Side Request Forgery)

- **严重等级:** HIGH
- **文件位置:** `src\transformers\pipelines\visual_question_answering.py:131`
- **数据流:** 用户输入通过__call__方法的image参数传入，经过inputs字典传递到preprocess方法，最终调用load_image函数。用户可以提供任意URL（包括内网地址），load_image会发起HTTP请求获取图片。
- **判断理由:** load_image函数接受用户提供的image参数，该参数可以是HTTP URL。如果用户提供内网地址（如http://localhost:8080/admin）或云服务元数据地址（如http://169.254.169.254/），服务器会发起请求，导致SSRF漏洞。攻击者可以利用此漏洞探测内网服务、访问云服务元数据等。

**代码片段:**
```
image = load_image(inputs["image"], timeout=timeout)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-C02A00B2 - SSRF (Server-Side Request Forgery) 和请求超时缺失

- **严重等级:** HIGH
- **文件位置:** `src\transformers\pipelines\zero_shot_audio_classification.py:108`
- **数据流:** 用户输入(audio参数) -> 检查是否以http://或https://开头 -> 直接传入requests.get()发起HTTP请求，未设置timeout参数
- **判断理由:** 1. 用户通过`audios`参数传入的字符串如果以http://或https://开头，会直接作为URL传递给requests.get()发起请求，未对URL进行任何校验或白名单过滤，攻击者可以构造恶意URL发起SSRF攻击，访问内部网络资源。2. requests.get()调用未设置timeout参数，可能导致请求无限期阻塞，造成资源耗尽或拒绝服务攻击。

**代码片段:**
```
audio = requests.get(audio).content
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-C195EB4B - SSRF (Server-Side Request Forgery)

- **严重等级:** MEDIUM
- **文件位置:** `src\transformers\pipelines\zero_shot_image_classification.py:106`
- **数据流:** 用户输入的images参数（可以是URL字符串） -> __call__方法 -> preprocess方法 -> load_image(image, timeout=timeout) -> 发起网络请求获取图片
- **判断理由:** load_image函数接受用户提供的URL并直接发起网络请求。用户可以通过传入内网地址（如http://localhost:8080, http://192.168.1.1等）来触发SSRF攻击，探测内网服务或访问内部资源。虽然timeout参数可以设置超时，但没有对URL进行任何校验或白名单限制。

**代码片段:**
```
image = load_image(image, timeout=timeout)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-FDBE899D - Missing Request Timeout

- **严重等级:** MEDIUM
- **文件位置:** `src\transformers\utils\hub.py:208`
- **数据流:** 代码中使用了requests库进行HTTP请求，但没有设置timeout参数，可能导致请求无限期挂起
- **判断理由:** Bandit静态分析工具检测到第208行存在requests调用没有设置timeout的问题。缺少timeout会导致网络请求在服务端无响应时无限期阻塞，可能造成资源耗尽或拒绝服务攻击。

**代码片段:**
```
requests without timeout
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-83C1BED2 - XSS (跨站脚本攻击)

- **严重等级:** HIGH
- **文件位置:** `src\transformers\utils\notebook.py:40`
- **数据流:** 用户输入通过prefix和label参数传入 -> html_progress_bar函数直接拼接HTML字符串 -> 返回给display()方法渲染
- **判断理由:** html_progress_bar函数直接将prefix和label参数拼接到HTML字符串中，没有进行任何HTML转义。这些参数可能包含用户可控的输入，当在Jupyter Notebook中通过IPython.display.HTML渲染时，恶意JavaScript代码会被执行，导致XSS攻击。

**代码片段:**
```
def html_progress_bar(value, total, prefix, label, width=300):
    return f"""
    <div>
      {prefix}
      <progress value='{value}' max='{total}' style='width:{width}px; height:20px; vertical-align: middle;'></progress>
      {label}
    </div>
    """
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B4B25E7D - XSS (跨站脚本攻击)

- **严重等级:** HIGH
- **文件位置:** `src\transformers\utils\notebook.py:50`
- **数据流:** 用户输入通过items参数传入 -> text_to_html_table函数直接拼接HTML字符串 -> 返回给调用方渲染
- **判断理由:** text_to_html_table函数将items中的内容直接拼接到HTML表格中，没有进行任何HTML转义。如果items包含用户可控的数据，恶意HTML/JavaScript代码会被注入并执行，导致XSS攻击。

**代码片段:**
```
def text_to_html_table(items):
    "Put the texts in `items` in an HTML table."
    html_code = """<table border="1" class="dataframe">\n"""
    html_code += """  <thead>\n <tr style="text-align: left;">\n"""
    for i in items[0]:
        html_code += f"      <th>{i}</th>\n"
    html_code += "    </tr>\n  </thead>\n  <tbody>\n"
    for line in items[1:]:
        html_code += "    <tr>\n"
        for elt in line:
            elt = f"{elt:.6f}" if isinstance(elt, float) else str(elt)
            html_code += f"      <td>{elt}</td>\n"
        html_code += "    </tr>\n"
    html_code += "  </tbody>\n</table><p>"
    return html_code
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-7E120B37 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests\quantization\hqq\test_hqq.py:47`
- **数据流:** MODEL_ID constant (line 82) -> HQQLLMRunner.__init__() parameter model_id (line 37) -> AutoTokenizer.from_pretrained() (line 47)
- **判断理由:** Similar to line 39, the AutoTokenizer.from_pretrained() call does not specify a 'revision' parameter. This means the tokenizer will be downloaded from Hugging Face Hub without pinning to a specific version, creating a supply chain vulnerability where the tokenizer could be silently replaced with a malicious version.

**代码片段:**
```
self.tokenizer = AutoTokenizer.from_pretrained(model_id, cache_dir=cache_dir)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-753AD18F - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests\quantization\quanto_integration\test_quanto.py:56`
- **数据流:** self.model_id = 'facebook/opt-350m' → AutoConfig.from_pretrained(self.model_id) → 从Hugging Face Hub下载模型配置，未指定revision参数
- **判断理由:** from_pretrained()调用未指定revision参数，将下载模型的最新版本。如果模型仓库被恶意更新，可能导致下载包含后门的模型版本。虽然这是测试代码，但测试环境可能连接到外部网络，存在供应链攻击风险。

**代码片段:**
```
config = AutoConfig.from_pretrained(self.model_id)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-136DFFEC - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests\quantization\quanto_integration\test_quanto.py:152`
- **数据流:** self.model_name = 'bigscience/bloom-560m' → AutoModelForCausalLM.from_pretrained() → 从Hugging Face Hub下载模型权重，未指定revision参数
- **判断理由:** from_pretrained()调用未指定revision参数，将下载模型的最新版本。如果模型仓库被恶意更新，可能导致下载包含后门的模型版本。虽然这是测试代码，但测试环境可能连接到外部网络，存在供应链攻击风险。

**代码片段:**
```
self.quantized_model = AutoModelForCausalLM.from_pretrained(
            self.model_name,
            device_map=self.device_map,
            quantization_config=quantization_config,
            torch_dtype=torch.float32,
        )
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-DFCC8C5F - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests\quantization\quanto_integration\test_quanto.py:159`
- **数据流:** self.model_name = 'bigscience/bloom-560m' → AutoTokenizer.from_pretrained(self.model_name) → 从Hugging Face Hub下载tokenizer，未指定revision参数
- **判断理由:** from_pretrained()调用未指定revision参数，将下载tokenizer的最新版本。如果tokenizer文件被恶意修改，可能导致代码执行或数据泄露。

**代码片段:**
```
self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B96AE144 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests\quantization\quanto_integration\test_quanto.py:262`
- **数据流:** self.model_name = 'bigscience/bloom-560m' → AutoModelForCausalLM.from_pretrained() → 从Hugging Face Hub下载模型权重，未指定revision参数
- **判断理由:** from_pretrained()调用未指定revision参数，将下载模型的最新版本。如果模型仓库被恶意更新，可能导致下载包含后门的模型版本。

**代码片段:**
```
self.quantized_model = AutoModelForCausalLM.from_pretrained(
            self.model_name,
            device_map=self.device_map,
            quantization_config=quantization_config,
            torch_dtype=torch.float32,
        )
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-46B8B929 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests\quantization\quanto_integration\test_quanto.py:280`
- **数据流:** self.model_name = 'bigscience/bloom-560m' → AutoModelForCausalLM.from_pretrained() → 从Hugging Face Hub下载模型权重，未指定revision参数
- **判断理由:** from_pretrained()调用未指定revision参数，将下载模型的最新版本。如果模型仓库被恶意更新，可能导致下载包含后门的模型版本。

**代码片段:**
```
self.quantized_model = AutoModelForCausalLM.from_pretrained(
            self.model_name,
            device_map=self.device_map,
            quantization_config=quantization_config,
            torch_dtype=torch.float32,
        )
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-27B624A1 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests\quantization\quanto_integration\test_quanto.py:294`
- **数据流:** self.model_name = 'bigscience/bloom-560m' → AutoModelForCausalLM.from_pretrained() → 从Hugging Face Hub下载模型权重，未指定revision参数
- **判断理由:** from_pretrained()调用未指定revision参数，将下载模型的最新版本。如果模型仓库被恶意更新，可能导致下载包含后门的模型版本。

**代码片段:**
```
self.quantized_model = AutoModelForCausalLM.from_pretrained(
            self.model_name,
            device_map=self.device_map,
            quantization_config=quantization_config,
            torch_dtype=torch.float32,
        )
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-31C20892 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests\quantization\quanto_integration\test_quanto.py:390`
- **数据流:** self.model_name = 'bigscience/bloom-560m' → AutoModelForCausalLM.from_pretrained() → 从Hugging Face Hub下载模型权重，未指定revision参数
- **判断理由:** from_pretrained()调用未指定revision参数，将下载模型的最新版本。如果模型仓库被恶意更新，可能导致下载包含后门的模型版本。

**代码片段:**
```
self.quantized_model = AutoModelForCausalLM.from_pretrained(
            self.model_name,
            device_map=self.device_map,
            quantization_config=quantization_config,
            torch_dtype=torch.float32,
        )
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-C2CAC5EF - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests\quantization\quanto_integration\test_quanto.py:398`
- **数据流:** self.model_name = 'bigscience/bloom-560m' → AutoModelForCausalLM.from_pretrained() → 从Hugging Face Hub下载模型权重，未指定revision参数
- **判断理由:** from_pretrained()调用未指定revision参数，将下载模型的最新版本。如果模型仓库被恶意更新，可能导致下载包含后门的模型版本。

**代码片段:**
```
self.quantized_model = AutoModelForCausalLM.from_pretrained(
            self.model_name,
            device_map=self.device_map,
            quantization_config=quantization_config,
            torch_dtype=torch.float32,
        )
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-2C81E0C6 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests\quantization\quanto_integration\test_quanto.py:402`
- **数据流:** self.model_name = 'bigscience/bloom-560m' → AutoTokenizer.from_pretrained(self.model_name) → 从Hugging Face Hub下载tokenizer，未指定revision参数
- **判断理由:** from_pretrained()调用未指定revision参数，将下载tokenizer的最新版本。如果tokenizer文件被恶意修改，可能导致代码执行或数据泄露。

**代码片段:**
```
self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-A96BFF8F - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests\quantization\quanto_integration\test_quanto.py:442`
- **数据流:** self.model_name = 'bigscience/bloom-560m' → AutoModelForCausalLM.from_pretrained() → 从Hugging Face Hub下载模型权重，未指定revision参数
- **判断理由:** from_pretrained()调用未指定revision参数，将下载模型的最新版本。如果模型仓库被恶意更新，可能导致下载包含后门的模型版本。

**代码片段:**
```
self.quantized_model = AutoModelForCausalLM.from_pretrained(
            self.model_name,
            device_map=self.device_map,
            quantization_config=quantization_config,
            torch_dtype=torch.float32,
        )
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-07754FE5 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests\quantization\quanto_integration\test_quanto.py:461`
- **数据流:** self.model_name = 'bigscience/bloom-560m' → AutoModelForCausalLM.from_pretrained() → 从Hugging Face Hub下载模型权重，未指定revision参数
- **判断理由:** from_pretrained()调用未指定revision参数，将下载模型的最新版本。如果模型仓库被恶意更新，可能导致下载包含后门的模型版本。

**代码片段:**
```
self.quantized_model = AutoModelForCausalLM.from_pretrained(
            self.model_name,
            device_map=self.device_map,
            quantization_config=quantization_config,
            torch_dtype=torch.float32,
        )
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-F0CB19FF - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests\quantization\quanto_integration\test_quanto.py:462`
- **数据流:** self.model_name = 'bigscience/bloom-560m' → AutoTokenizer.from_pretrained(self.model_name) → 从Hugging Face Hub下载tokenizer，未指定revision参数
- **判断理由:** from_pretrained()调用未指定revision参数，将下载tokenizer的最新版本。如果tokenizer文件被恶意修改，可能导致代码执行或数据泄露。

**代码片段:**
```
self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-D55A71A3 - 硬编码凭证

- **严重等级:** HIGH
- **文件位置:** `tests/sagemaker/conftest.py:14`
- **数据流:** 静态赋值 -> SageMakerTestEnvironment.role属性 -> 可能被测试代码使用
- **判断理由:** 代码中硬编码了AWS IAM角色的ARN，包含AWS账号ID(558105141721)和角色名称。这属于敏感凭证信息，如果代码被提交到公共仓库，攻击者可以利用此信息进行社会工程攻击或尝试利用该角色。虽然这是一个测试文件，但硬编码凭证仍然是不安全的做法。

**代码片段:**
```
role = "arn:aws:iam::558105141721:role/sagemaker_execution_role"
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-AD04503B - 硬编码凭证

- **严重等级:** MEDIUM
- **文件位置:** `tests/sagemaker/conftest.py:6`
- **数据流:** 环境变量设置 -> 影响AWS SDK行为
- **判断理由:** 代码中硬编码了AWS默认区域，虽然区域信息本身不是敏感凭证，但结合硬编码的IAM角色ARN，暴露了测试环境的具体配置信息，可能被用于针对性攻击。

**代码片段:**
```
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-4B83E7AA - 命令注入

- **严重等级:** HIGH
- **文件位置:** `tests\sagemaker\test_multi_node_data_parallel.py:47`
- **数据流:** self.env.test_path 来自测试环境配置，可能包含用户可控的路径值 -> 直接拼接到subprocess.run的命令字符串中 -> 执行系统命令
- **判断理由:** subprocess.run使用了f-string拼接命令字符串，其中{self.env.test_path}来自外部环境变量或配置。如果攻击者能够控制test_path的值，可以注入额外的命令参数或路径遍历字符，导致任意命令执行。虽然使用了.split()分割参数，但路径中的空格或特殊字符仍可能导致命令注入。

**代码片段:**
```
subprocess.run(
                f"cp ./examples/pytorch/text-classification/run_glue.py {self.env.test_path}/run_glue.py".split(),
                encoding="utf-8",
                check=True,
            )
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-36D509E4 - 路径遍历

- **严重等级:** MEDIUM
- **文件位置:** `tests\sagemaker\test_multi_node_data_parallel.py:47`
- **数据流:** self.env.test_path 可能包含路径遍历序列(如../) -> 拼接到目标路径 -> 文件被复制到预期目录之外
- **判断理由:** 目标路径{self.env.test_path}/run_glue.py中，test_path未经过路径规范化或白名单校验。如果test_path包含../等路径遍历字符，可能导致文件被复制到任意位置，覆盖重要文件。

**代码片段:**
```
subprocess.run(
                f"cp ./examples/pytorch/text-classification/run_glue.py {self.env.test_path}/run_glue.py".split(),
                encoding="utf-8",
                check=True,
            )
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-448E9B63 - 路径遍历

- **严重等级:** MEDIUM
- **文件位置:** `tests\sagemaker\test_multi_node_data_parallel.py:68`
- **数据流:** self.env.test_path 可能包含路径遍历序列 -> 拼接到CSV导出路径 -> 文件写入到预期目录之外
- **判断理由:** export_csv的目标路径使用了f-string拼接，其中test_path来自外部环境。如果test_path包含路径遍历字符，CSV文件可能被写入到任意目录，造成信息泄露或文件覆盖。

**代码片段:**
```
TrainingJobAnalytics(job_name).export_csv(f"{self.env.test_path}/{job_name}_metrics.csv")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-3DF1CB3B - 路径遍历

- **严重等级:** MEDIUM
- **文件位置:** `tests\sagemaker\test_multi_node_data_parallel.py:97`
- **数据流:** estimator.latest_training_job.name 来自SageMaker训练任务名称 -> 直接作为文件名 -> 写入JSON文件
- **判断理由:** 训练任务名称可能包含路径分隔符或特殊字符，直接用作文件名可能导致路径遍历或文件写入到意外位置。虽然SageMaker任务名称通常由系统生成，但如果攻击者能够控制任务名称，可能造成任意文件写入。

**代码片段:**
```
with open(f"{estimator.latest_training_job.name}.json", "w") as outfile:
            json.dump({"train_time": train_runtime, "eval_accuracy": eval_accuracy, "eval_loss": eval_loss}, outfile)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-D68EC395 - 不安全的临时文件创建

- **严重等级:** LOW
- **文件位置:** `tests\sagemaker\test_multi_node_data_parallel.py:97`
- **数据流:** 文件创建在当前工作目录 -> 使用固定文件名模式 -> 可能被其他进程预测或劫持
- **判断理由:** JSON文件创建在当前工作目录，文件名基于训练任务名称，没有使用安全的临时文件创建机制(如tempfile模块)。在多用户或共享环境中，其他进程可能预测文件名并进行符号链接攻击，导致文件内容被篡改或信息泄露。

**代码片段:**
```
with open(f"{estimator.latest_training_job.name}.json", "w") as outfile:
            json.dump({"train_time": train_runtime, "eval_accuracy": eval_accuracy, "eval_loss": eval_loss}, outfile)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-E32A15FD - 命令注入

- **严重等级:** HIGH
- **文件位置:** `tests/sagemaker/test_multi_node_model_parallel.py:42`
- **数据流:** self.env.test_path → f-string拼接 → subprocess.run()执行
- **判断理由:** self.env.test_path来自测试环境变量，可能被攻击者控制。代码使用f-string直接拼接用户输入到shell命令中，虽然使用了.split()分割参数，但test_path如果包含空格或特殊字符，可能导致命令注入。攻击者可以通过控制test_path环境变量执行任意命令。

**代码片段:**
```
subprocess.run(
                f"cp ./examples/pytorch/text-classification/run_glue.py {self.env.test_path}/run_glue.py".split(),
                encoding="utf-8",
                check=True,
            )
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-C7FDCF66 - 路径遍历

- **严重等级:** MEDIUM
- **文件位置:** `tests/sagemaker/test_multi_node_model_parallel.py:42`
- **数据流:** self.env.test_path → 文件路径拼接 → cp命令目标路径
- **判断理由:** self.env.test_path直接用于构建文件复制目标路径，如果test_path包含'../'等路径遍历序列，攻击者可以将文件复制到任意目录，造成文件覆盖或信息泄露。

**代码片段:**
```
subprocess.run(
                f"cp ./examples/pytorch/text-classification/run_glue.py {self.env.test_path}/run_glue.py".split(),
                encoding="utf-8",
                check=True,
            )
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-C9A0102A - 路径遍历

- **严重等级:** MEDIUM
- **文件位置:** `tests/sagemaker/test_multi_node_model_parallel.py:73`
- **数据流:** self.env.test_path → f-string拼接 → export_csv文件路径
- **判断理由:** self.env.test_path直接用于构建CSV文件导出路径，如果test_path包含路径遍历字符，可能导致文件写入到非预期位置。

**代码片段:**
```
TrainingJobAnalytics(job_name).export_csv(f"{self.env.test_path}/{job_name}_metrics.csv")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-2BE66778 - 路径遍历

- **严重等级:** MEDIUM
- **文件位置:** `tests/sagemaker/test_multi_node_model_parallel.py:101`
- **数据流:** estimator.latest_training_job.name → f-string拼接 → open()文件路径
- **判断理由:** estimator.latest_training_job.name来自SageMaker训练任务名称，虽然通常由AWS生成，但如果攻击者能够控制训练任务名称，则可能导致路径遍历攻击，将JSON文件写入任意位置。

**代码片段:**
```
with open(f"{estimator.latest_training_job.name}.json", "w") as outfile:
            json.dump({"train_time": train_runtime, "eval_accuracy": eval_accuracy, "eval_loss": eval_loss}, outfile)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-8ACF9224 - 不安全的临时文件创建

- **严重等级:** LOW
- **文件位置:** `tests/sagemaker/test_multi_node_model_parallel.py:101`
- **数据流:** 直接在当前目录创建文件，无随机化处理
- **判断理由:** 代码直接使用训练任务名称作为文件名创建JSON文件，没有使用临时文件创建机制（如tempfile模块），也没有添加随机后缀。在多线程或多进程环境下可能导致文件竞争条件，且文件可能被其他进程预测和访问。

**代码片段:**
```
with open(f"{estimator.latest_training_job.name}.json", "w") as outfile:
            json.dump({"train_time": train_runtime, "eval_accuracy": eval_accuracy, "eval_loss": eval_loss}, outfile)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-E431C319 - 命令注入

- **严重等级:** HIGH
- **文件位置:** `tests/sagemaker/test_single_node_gpu.py:42`
- **数据流:** self.env.test_path 来自测试环境配置 → 直接拼接到subprocess.run的命令字符串中 → 执行系统命令
- **判断理由:** subprocess.run使用了f-string拼接用户可控的路径参数self.env.test_path，虽然当前是测试代码，但如果test_path包含恶意字符（如分号、管道符等），可能导致命令注入。攻击者可利用此漏洞执行任意系统命令。

**代码片段:**
```
subprocess.run(
    f"cp ./examples/pytorch/text-classification/run_glue.py {self.env.test_path}/run_glue.py".split(),
    encoding="utf-8",
    check=True,
)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-44888256 - 路径遍历

- **严重等级:** MEDIUM
- **文件位置:** `tests/sagemaker/test_single_node_gpu.py:42`
- **数据流:** self.env.test_path 用户可控 → 直接用于文件路径构造 → 文件复制操作
- **判断理由:** self.env.test_path直接拼接到文件路径中，未进行路径规范化或合法性校验。如果test_path包含'../'等路径遍历字符，可能导致文件被复制到预期目录之外的位置，造成信息泄露或文件覆盖。

**代码片段:**
```
f"cp ./examples/pytorch/text-classification/run_glue.py {self.env.test_path}/run_glue.py"
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-70A85F85 - 路径遍历

- **严重等级:** MEDIUM
- **文件位置:** `tests/sagemaker/test_single_node_gpu.py:60`
- **数据流:** self.env.test_path 用户可控 → 直接拼接到文件路径 → 文件写入操作
- **判断理由:** self.env.test_path直接拼接到CSV文件导出路径中，未进行路径校验。攻击者可通过控制test_path参数将文件写入任意目录，可能导致敏感文件被覆盖或创建恶意文件。

**代码片段:**
```
TrainingJobAnalytics(job_name).export_csv(f"{self.env.test_path}/{job_name}_metrics.csv")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B73A51F5 - 路径遍历

- **严重等级:** MEDIUM
- **文件位置:** `tests/sagemaker/test_single_node_gpu.py:88`
- **数据流:** estimator.latest_training_job.name 来自SageMaker训练任务名称 → 直接用于文件路径 → 文件写入操作
- **判断理由:** 训练任务名称直接用于构造JSON文件路径，未进行路径清理。如果训练任务名称包含路径分隔符或特殊字符，可能导致文件写入到非预期位置，造成路径遍历攻击。

**代码片段:**
```
with open(f"{estimator.latest_training_job.name}.json", "w") as outfile:
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-EBBFEF90 - 命令注入

- **严重等级:** CRITICAL
- **文件位置:** `tests\sagemaker\scripts\pytorch\run_ddp.py:46`
- **数据流:** 用户通过命令行参数传入args -> parse_args()解析为args.__dict__ -> 在main()中通过f-string拼接成cmd字符串 -> subprocess.run(cmd, shell=True)执行
- **判断理由:** 代码使用subprocess.run()并设置shell=True执行命令，且命令字符串通过f-string直接拼接用户输入的参数(args.__dict__)。攻击者可以通过构造恶意参数(如包含分号、管道符等)注入任意命令，导致远程代码执行。

**代码片段:**
```
subprocess.run(cmd, shell=True)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-004B66C7 - 命令注入

- **严重等级:** CRITICAL
- **文件位置:** `tests\sagemaker\scripts\pytorch\run_ddp.py:37`
- **数据流:** 用户输入通过命令行参数传入args -> args.__dict__中的parameter和value直接拼接到cmd字符串中 -> subprocess.run(cmd, shell=True)执行
- **判断理由:** 命令字符串中直接拼接了用户可控的args.__dict__内容，parameter和value均未经过任何过滤或转义。攻击者可以注入恶意shell命令，例如通过value参数传入'; rm -rf /'等。

**代码片段:**
```
cmd = f"""python -m torch.distributed.launch \
                --nnodes={num_nodes}  \
                --node_rank={rank}  \
                --nproc_per_node={num_gpus}  \
                --master_addr={hosts[0]}  \
                --master_port={port} \
                ./run_glue.py \
                {"".join([f" --{parameter} {value}" for parameter,value in args.__dict__.items()])}"""
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-1B1D23E5 - 命令注入

- **严重等级:** CRITICAL
- **文件位置:** `tests\sagemaker\scripts\pytorch\run_ddp.py:43`
- **数据流:** 用户输入通过命令行参数传入args -> args.__dict__中的parameter和value直接拼接到cmd字符串中 -> subprocess.run(cmd, shell=True)执行
- **判断理由:** 与第37行类似，在单节点场景下同样存在命令注入风险。用户可控的args.__dict__内容直接拼接到shell命令中，可被利用执行任意命令。

**代码片段:**
```
cmd = f"""python -m torch.distributed.launch \
            --nproc_per_node={num_gpus}  \
            ./run_glue.py \
            {"".join([f" --{parameter} {value}" for parameter,value in args.__dict__.items()])}"""
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-567336E6 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests\sagemaker\scripts\pytorch\run_glue_model_parallelism.py:256`
- **数据流:** load_dataset() is called without specifying a revision parameter, which means it will download the latest version of the dataset from Hugging Face Hub. If the dataset is updated maliciously, the script could download and execute untrusted data.
- **判断理由:** Bandit static analysis flagged this as B615. The load_dataset() function downloads datasets from Hugging Face Hub. Without pinning to a specific revision (commit hash, tag, or branch), the script will always fetch the latest version. This could lead to supply chain attacks if a dataset maintainer or attacker pushes malicious updates.

**代码片段:**
```
load_dataset(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-98141E6F - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests\sagemaker\scripts\pytorch\run_glue_model_parallelism.py:280`
- **数据流:** load_dataset() is called without specifying a revision parameter, which means it will download the latest version of the dataset from Hugging Face Hub. If the dataset is updated maliciously, the script could download and execute untrusted data.
- **判断理由:** Bandit static analysis flagged this as B615. The load_dataset() function downloads datasets from Hugging Face Hub. Without pinning to a specific revision (commit hash, tag, or branch), the script will always fetch the latest version. This could lead to supply chain attacks if a dataset maintainer or attacker pushes malicious updates.

**代码片段:**
```
load_dataset(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-291D4A01 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests\sagemaker\scripts\pytorch\run_glue_model_parallelism.py:283`
- **数据流:** load_dataset() is called without specifying a revision parameter, which means it will download the latest version of the dataset from Hugging Face Hub. If the dataset is updated maliciously, the script could download and execute untrusted data.
- **判断理由:** Bandit static analysis flagged this as B615. The load_dataset() function downloads datasets from Hugging Face Hub. Without pinning to a specific revision (commit hash, tag, or branch), the script will always fetch the latest version. This could lead to supply chain attacks if a dataset maintainer or attacker pushes malicious updates.

**代码片段:**
```
load_dataset(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-A686ECA9 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests\sagemaker\scripts\pytorch\run_glue_model_parallelism.py:470`
- **数据流:** from_pretrained() is called without specifying a revision parameter, which means it will download the latest version of the model from Hugging Face Hub. If the model is updated maliciously, the script could download and execute untrusted model weights.
- **判断理由:** Bandit static analysis flagged this as B615. The from_pretrained() function downloads model weights and configuration from Hugging Face Hub. Without pinning to a specific revision (commit hash, tag, or branch), the script will always fetch the latest version. This could lead to supply chain attacks if a model maintainer or attacker pushes malicious updates containing backdoored weights or code.

**代码片段:**
```
from_pretrained(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-A95E6BAE - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests\sagemaker\scripts\tensorflow\run_tf.py:55`
- **数据流:** 用户通过命令行参数 --model_name_or_path 传入模型名称或路径，直接传递给 from_pretrained() 方法，未指定 revision 参数固定版本
- **判断理由:** from_pretrained() 方法未指定 revision 参数，默认会从 Hugging Face Hub 下载最新版本的模型。攻击者可能上传恶意模型到同名仓库，或利用仓库维护者账号被攻陷后推送恶意代码，导致供应链攻击。用户输入直接控制下载源，增加了攻击面。

**代码片段:**
```
model = TFAutoModelForSequenceClassification.from_pretrained(args.model_name_or_path)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-7341B9D4 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests\sagemaker\scripts\tensorflow\run_tf.py:56`
- **数据流:** 用户通过命令行参数 --model_name_or_path 传入模型名称或路径，直接传递给 from_pretrained() 方法，未指定 revision 参数固定版本
- **判断理由:** 与第55行相同的问题，tokenizer的加载也未指定revision参数。攻击者可能通过控制模型仓库中的tokenizer配置文件来植入恶意代码，导致代码执行或数据泄露。

**代码片段:**
```
tokenizer = AutoTokenizer.from_pretrained(args.model_name_or_path)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-D6D8E782 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests\sagemaker\scripts\tensorflow\run_tf.py:59`
- **数据流:** 硬编码的数据集名称 'stanfordnlp/imdb' 传递给 load_dataset() 方法，未指定 revision 参数
- **判断理由:** 虽然数据集名称是硬编码的，但未指定 revision 参数意味着每次运行都会下载最新版本的数据集。如果数据集维护者更新了数据集内容（可能包含恶意数据），或者仓库被攻陷，可能导致模型训练受到污染。风险相对较低因为数据集名称是固定的，但仍存在供应链风险。

**代码片段:**
```
train_dataset, test_dataset = load_dataset("stanfordnlp/imdb", split=["train", "test"])
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-5C4354D7 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/sagemaker/scripts/tensorflow/run_tf_dist.py:53`
- **数据流:** 用户未指定revision参数，load_dataset()从Hugging Face Hub下载数据集时使用默认的main分支，可能被恶意更新导致供应链攻击
- **判断理由:** load_dataset()未指定revision参数，默认使用main分支的最新版本。攻击者可能通过篡改Hugging Face Hub上的数据集版本，引入恶意数据或代码，导致训练过程被污染或执行恶意操作。

**代码片段:**
```
train_dataset, test_dataset = load_dataset("stanfordnlp/imdb", split=["train", "test"])
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-A4E51D6A - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/sagemaker/scripts/tensorflow/run_tf_dist.py:128`
- **数据流:** 用户通过命令行参数--model_name_or_path指定模型路径，但未指定revision参数，from_pretrained()从Hugging Face Hub下载模型时使用默认的main分支，可能被恶意更新
- **判断理由:** from_pretrained()未指定revision参数，默认使用main分支的最新版本。攻击者可能通过篡改Hugging Face Hub上的模型版本，引入恶意权重或代码，导致模型加载时执行恶意操作。

**代码片段:**
```
model = TFAutoModelForSequenceClassification.from_pretrained(args.model_name_or_path)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-7640E324 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/sagemaker/scripts/tensorflow/run_tf_dist.py:129`
- **数据流:** 用户通过命令行参数--model_name_or_path指定tokenizer路径，但未指定revision参数，from_pretrained()从Hugging Face Hub下载tokenizer时使用默认的main分支，可能被恶意更新
- **判断理由:** from_pretrained()未指定revision参数，默认使用main分支的最新版本。攻击者可能通过篡改Hugging Face Hub上的tokenizer版本，引入恶意配置或代码，导致tokenizer加载时执行恶意操作。

**代码片段:**
```
tokenizer = AutoTokenizer.from_pretrained(args.model_name_or_path)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-896AE83F - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/tokenization/test_tokenization_fast.py:47`
- **数据流:** from_pretrained() is called with model_paths[0] which is 'robot-test/dummy-tokenizer-fast' without specifying a revision parameter. This allows downloading arbitrary versions of the model from Hugging Face Hub.
- **判断理由:** The from_pretrained() method downloads model files from Hugging Face Hub. Without pinning a specific revision (commit hash, tag, or branch), the downloaded content could change at any time if the repository is updated. This is a supply chain security risk as it could lead to downloading malicious code or weights.

**代码片段:**
```
tokenizer = PreTrainedTokenizerFast.from_pretrained(model_paths[0])
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-CFA79FFA - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/tokenization/test_tokenization_fast.py:147`
- **数据流:** from_pretrained() is called with pretrained_name from self.tokenizers_list which includes 'robot-test/dummy-tokenizer-fast' and 'robot-test/dummy-tokenizer-wordlevel' without revision pinning.
- **判断理由:** Same vulnerability as above. The pretrained_name variable contains model identifiers from Hugging Face Hub without a pinned revision, making the download susceptible to supply chain attacks.

**代码片段:**
```
tokenizer = self.rust_tokenizer_class.from_pretrained(pretrained_name, **kwargs)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-EE10DDFD - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/tokenization/test_tokenization_fast.py:163`
- **数据流:** from_pretrained() is called with pretrained_name from self.tokenizers_list without revision pinning.
- **判断理由:** Same vulnerability pattern. The download lacks revision pinning, allowing potential malicious updates to the model repository to affect the test execution.

**代码片段:**
```
tokenizer = self.rust_tokenizer_class.from_pretrained(pretrained_name, **kwargs)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-4C2CD3EA - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/tokenization/test_tokenization_fast.py:177`
- **数据流:** from_pretrained() is called with self.bytelevel_bpe_model_name which is 'SaulLu/dummy-tokenizer-bytelevel-bpe' without revision pinning.
- **判断理由:** Same vulnerability. The bytelevel BPE model is downloaded without specifying a revision, creating a supply chain risk.

**代码片段:**
```
tokenizer = self.rust_tokenizer_class.from_pretrained(self.bytelevel_bpe_model_name)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-05D01799 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/tokenization/test_tokenization_fast.py:188`
- **数据流:** Tokenizer.from_pretrained() is called with 'google-t5/t5-base' without revision pinning.
- **判断理由:** Same vulnerability. The tokenizers library's from_pretrained() method also downloads from Hugging Face Hub without a pinned revision, exposing the test to supply chain attacks.

**代码片段:**
```
tokenizer = Tokenizer.from_pretrained("google-t5/t5-base")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-79FB1685 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/tokenization/test_tokenization_fast.py:198`
- **数据流:** from_pretrained() is called with tmpdirname which is a local directory path, not a Hugging Face Hub model ID.
- **判断理由:** This call uses a local directory path (tmpdirname) rather than a remote model ID, so it does not download from Hugging Face Hub. However, it still lacks revision pinning which is not applicable for local paths. This is a false positive from the static analysis tool.

**代码片段:**
```
fast_from_saved = PreTrainedTokenizerFast.from_pretrained(tmpdirname)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-91FD6A2C - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/tokenization/test_tokenization_fast.py:208`
- **数据流:** from_pretrained() is called with tmpdirname which is a local directory path.
- **判断理由:** Same as above - this uses a local path, not a remote model ID. The static analysis tool may have flagged this incorrectly.

**代码片段:**
```
fast_from_saved = PreTrainedTokenizerFast.from_pretrained(tmpdirname)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-24CD4230 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/tokenization/test_tokenization_fast.py:217`
- **数据流:** from_pretrained() is called with tmpdirname which is a local directory path.
- **判断理由:** Same as above - local path usage, not a remote download. False positive from static analysis.

**代码片段:**
```
fast_from_saved = PreTrainedTokenizerFast.from_pretrained(tmpdirname)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-13D1D978 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/tokenization/test_tokenization_fast.py:228`
- **数据流:** from_pretrained() is called with tmpdirname which is a local directory path.
- **判断理由:** Same as above - local path usage, not a remote download. False positive from static analysis.

**代码片段:**
```
fast_from_saved = PreTrainedTokenizerFast.from_pretrained(tmpdirname)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-E49061A2 - 不安全的反序列化

- **严重等级:** HIGH
- **文件位置:** `tests/tokenization/test_tokenization_utils.py:64`
- **数据流:** pickle.dumps()序列化BatchEncoding对象 -> pickle.loads()反序列化同一对象。虽然当前代码中数据来自内部序列化，但pickle.loads()本身存在安全风险，如果序列化数据被篡改或来自不可信源，可能导致任意代码执行。
- **判断理由:** 使用pickle.loads()反序列化数据存在安全风险。pickle协议在反序列化时会执行任意Python代码，如果攻击者能够控制序列化数据，可能导致远程代码执行。虽然当前场景中数据来自内部序列化，但该模式容易被复制到其他不安全场景。

**代码片段:**
```
batch_encoding_str = pickle.dumps(be_original)
self.assertIsNotNone(batch_encoding_str)

be_restored = pickle.loads(batch_encoding_str)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-E0937D60 - 不安全的Hugging Face Hub下载（无版本锁定）

- **严重等级:** MEDIUM
- **文件位置:** `tests/tokenization/test_tokenization_utils.py:95`
- **数据流:** from_pretrained()调用未指定revision参数 -> 从Hugging Face Hub下载最新版本模型
- **判断理由:** from_pretrained()未指定revision参数，将下载模型的最新版本。如果模型仓库被恶意更新，或存在供应链攻击，测试将使用被篡改的模型，可能导致安全风险。建议指定具体的commit hash或版本标签。

**代码片段:**
```
tokenizer_p = BertTokenizer.from_pretrained("google-bert/bert-base-cased")
tokenizer_r = BertTokenizerFast.from_pretrained("google-bert/bert-base-cased")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-670B5C36 - 不安全的Hugging Face Hub下载（无版本锁定）

- **严重等级:** MEDIUM
- **文件位置:** `tests/tokenization/test_tokenization_utils.py:96`
- **数据流:** from_pretrained()调用未指定revision参数 -> 从Hugging Face Hub下载最新版本模型
- **判断理由:** 与第95行相同的问题，from_pretrained()未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
tokenizer_p = BertTokenizer.from_pretrained("google-bert/bert-base-cased")
tokenizer_r = BertTokenizerFast.from_pretrained("google-bert/bert-base-cased")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-4AB5B8E5 - 不安全的Hugging Face Hub下载（无版本锁定）

- **严重等级:** MEDIUM
- **文件位置:** `tests/tokenization/test_tokenization_utils.py:123`
- **数据流:** from_pretrained()调用未指定revision参数 -> 从Hugging Face Hub下载最新版本模型
- **判断理由:** from_pretrained()未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
tokenizer_p = BertTokenizer.from_pretrained("google-bert/bert-base-cased")
tokenizer_r = BertTokenizerFast.from_pretrained("google-bert/bert-base-cased")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-E13AAB30 - 不安全的Hugging Face Hub下载（无版本锁定）

- **严重等级:** MEDIUM
- **文件位置:** `tests/tokenization/test_tokenization_utils.py:124`
- **数据流:** from_pretrained()调用未指定revision参数 -> 从Hugging Face Hub下载最新版本模型
- **判断理由:** from_pretrained()未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
tokenizer_p = BertTokenizer.from_pretrained("google-bert/bert-base-cased")
tokenizer_r = BertTokenizerFast.from_pretrained("google-bert/bert-base-cased")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-99993114 - 不安全的Hugging Face Hub下载（无版本锁定）

- **严重等级:** MEDIUM
- **文件位置:** `tests/tokenization/test_tokenization_utils.py:141`
- **数据流:** from_pretrained()调用未指定revision参数 -> 从Hugging Face Hub下载最新版本模型
- **判断理由:** from_pretrained()未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
tokenizer_p = BertTokenizer.from_pretrained("google-bert/bert-base-cased")
tokenizer_r = BertTokenizerFast.from_pretrained("google-bert/bert-base-cased")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-8F145A74 - 不安全的Hugging Face Hub下载（无版本锁定）

- **严重等级:** MEDIUM
- **文件位置:** `tests/tokenization/test_tokenization_utils.py:142`
- **数据流:** from_pretrained()调用未指定revision参数 -> 从Hugging Face Hub下载最新版本模型
- **判断理由:** from_pretrained()未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
tokenizer_p = BertTokenizer.from_pretrained("google-bert/bert-base-cased")
tokenizer_r = BertTokenizerFast.from_pretrained("google-bert/bert-base-cased")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B93A645C - 不安全的Hugging Face Hub下载（无版本锁定）

- **严重等级:** MEDIUM
- **文件位置:** `tests/tokenization/test_tokenization_utils.py:156`
- **数据流:** from_pretrained()调用未指定revision参数 -> 从Hugging Face Hub下载最新版本模型
- **判断理由:** from_pretrained()未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
tokenizer_p = BertTokenizer.from_pretrained("google-bert/bert-base-cased")
tokenizer_r = BertTokenizerFast.from_pretrained("google-bert/bert-base-cased")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-CAAA7995 - 不安全的Hugging Face Hub下载（无版本锁定）

- **严重等级:** MEDIUM
- **文件位置:** `tests/tokenization/test_tokenization_utils.py:157`
- **数据流:** from_pretrained()调用未指定revision参数 -> 从Hugging Face Hub下载最新版本模型
- **判断理由:** from_pretrained()未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
tokenizer_p = BertTokenizer.from_pretrained("google-bert/bert-base-cased")
tokenizer_r = BertTokenizerFast.from_pretrained("google-bert/bert-base-cased")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-4D741963 - 不安全的Hugging Face Hub下载（无版本锁定）

- **严重等级:** MEDIUM
- **文件位置:** `tests/tokenization/test_tokenization_utils.py:167`
- **数据流:** from_pretrained()调用未指定revision参数 -> 从Hugging Face Hub下载最新版本模型
- **判断理由:** from_pretrained()未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
tokenizer_p = BertTokenizer.from_pretrained("google-bert/bert-base-cased")
tokenizer_r = BertTokenizerFast.from_pretrained("google-bert/bert-base-cased")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-624BC129 - 不安全的Hugging Face Hub下载（无版本锁定）

- **严重等级:** MEDIUM
- **文件位置:** `tests/tokenization/test_tokenization_utils.py:239`
- **数据流:** from_pretrained()调用未指定revision参数 -> 从Hugging Face Hub下载最新版本模型
- **判断理由:** from_pretrained()未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
tokenizer_r = BertTokenizerFast.from_pretrained("google-bert/bert-base-cased")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-86ACAE0F - 不安全的Hugging Face Hub下载（无版本锁定）

- **严重等级:** MEDIUM
- **文件位置:** `tests/tokenization/test_tokenization_utils.py:253`
- **数据流:** from_pretrained()调用未指定revision参数 -> 从Hugging Face Hub下载最新版本模型
- **判断理由:** from_pretrained()未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
tokenizer_r = BertTokenizerFast.from_pretrained("google-bert/bert-base-cased")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-2D4E6279 - 不安全的Hugging Face Hub下载（无版本锁定）

- **严重等级:** MEDIUM
- **文件位置:** `tests/tokenization/test_tokenization_utils.py:267`
- **数据流:** from_pretrained()调用未指定revision参数 -> 从Hugging Face Hub下载最新版本模型
- **判断理由:** from_pretrained()未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
tokenizer_r = BertTokenizerFast.from_pretrained("google-bert/bert-base-cased")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-CC6B616A - 不安全的PyTorch模型加载

- **严重等级:** CRITICAL
- **文件位置:** `tests/trainer/test_trainer.py:501`
- **数据流:** 静态工具报告第501行使用了torch.load()，未指定weights_only=True参数，可能导致任意代码执行
- **判断理由:** torch.load()默认使用pickle反序列化，可以执行任意Python代码。如果加载的模型文件来自不可信来源，攻击者可以构造恶意pickle数据执行任意命令。应使用weights_only=True参数限制只加载张量数据。

**代码片段:**
```
torch.load(...)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-FEA55185 - 不安全的HuggingFace Hub下载（未固定版本）

- **严重等级:** HIGH
- **文件位置:** `tests/trainer/test_trainer.py:971`
- **数据流:** 静态工具报告第971行调用了from_pretrained()但未指定revision参数固定模型版本
- **判断理由:** from_pretrained()未指定revision参数时，默认下载最新版本的模型。如果模型仓库被恶意更新，可能导致下载包含恶意代码的模型文件，造成任意代码执行。应使用revision参数固定到具体的commit hash或标签。

**代码片段:**
```
from_pretrained()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-C4C56B14 - 不安全的HuggingFace Hub下载（未固定版本）

- **严重等级:** HIGH
- **文件位置:** `tests/trainer/test_trainer.py:1006`
- **数据流:** 静态工具报告第1006行调用了from_pretrained()但未指定revision参数固定模型版本
- **判断理由:** 同上，from_pretrained()未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
from_pretrained()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-C7B89CC1 - 不安全的HuggingFace Hub下载（未固定版本）

- **严重等级:** HIGH
- **文件位置:** `tests/trainer/test_trainer.py:1007`
- **数据流:** 静态工具报告第1007行调用了from_pretrained()但未指定revision参数固定模型版本
- **判断理由:** 同上，from_pretrained()未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
from_pretrained()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-A95C80BA - 不安全的HuggingFace Hub下载（未固定版本）

- **严重等级:** HIGH
- **文件位置:** `tests/trainer/test_trainer.py:2768`
- **数据流:** 静态工具报告第2768行调用了from_pretrained()但未指定revision参数固定模型版本
- **判断理由:** 同上，from_pretrained()未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
from_pretrained()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-967CA1CD - 不安全的HuggingFace Hub下载（未固定版本）

- **严重等级:** HIGH
- **文件位置:** `tests/trainer/test_trainer.py:2769`
- **数据流:** 静态工具报告第2769行调用了from_pretrained()但未指定revision参数固定模型版本
- **判断理由:** 同上，from_pretrained()未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
from_pretrained()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-22271C16 - 不安全的HuggingFace Hub下载（未固定版本）

- **严重等级:** HIGH
- **文件位置:** `tests/trainer/test_trainer.py:2783`
- **数据流:** 静态工具报告第2783行调用了from_pretrained()但未指定revision参数固定模型版本
- **判断理由:** 同上，from_pretrained()未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
from_pretrained()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-6A64DAF4 - 不安全的HuggingFace Hub下载（未固定版本）

- **严重等级:** HIGH
- **文件位置:** `tests/trainer/test_trainer.py:2784`
- **数据流:** 静态工具报告第2784行调用了from_pretrained()但未指定revision参数固定模型版本
- **判断理由:** 同上，from_pretrained()未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
from_pretrained()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-FB96C06C - 不安全的HuggingFace Hub下载（未固定版本）

- **严重等级:** HIGH
- **文件位置:** `tests/trainer/test_trainer.py:2813`
- **数据流:** 静态工具报告第2813行调用了from_pretrained()但未指定revision参数固定模型版本
- **判断理由:** 同上，from_pretrained()未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
from_pretrained()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-565B4C20 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/trainer/test_trainer_seq2seq.py:39`
- **数据流:** from_pretrained() downloads model from Hugging Face Hub without specifying a revision (commit hash, tag, or branch), which could lead to downloading a different version than expected.
- **判断理由:** Without revision pinning, the downloaded model could change unexpectedly if the repository owner updates the default branch. This is a supply chain security risk as it could introduce malicious code or unexpected behavior changes.

**代码片段:**
```
bert2bert = EncoderDecoderModel.from_encoder_decoder_pretrained("prajjwal1/bert-tiny", "prajjwal1/bert-tiny")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B95F674D - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/trainer/test_trainer_seq2seq.py:40`
- **数据流:** from_pretrained() downloads tokenizer from Hugging Face Hub without specifying a revision.
- **判断理由:** Same supply chain risk as above - the tokenizer could change unexpectedly if the repository owner updates the default branch.

**代码片段:**
```
tokenizer = BertTokenizer.from_pretrained("google-bert/bert-base-uncased")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-DBBDB12E - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/trainer/test_trainer_seq2seq.py:46`
- **数据流:** load_dataset() downloads dataset from Hugging Face Hub without specifying a revision.
- **判断理由:** Without revision pinning, the dataset could change unexpectedly, potentially affecting test reproducibility and introducing data integrity issues.

**代码片段:**
```
train_dataset = datasets.load_dataset("abisee/cnn_dailymail", "3.0.0", split="train[:1%]")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-E27FD16D - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/trainer/test_trainer_seq2seq.py:47`
- **数据流:** load_dataset() downloads dataset from Hugging Face Hub without specifying a revision.
- **判断理由:** Same supply chain risk as above - the validation dataset could change unexpectedly.

**代码片段:**
```
val_dataset = datasets.load_dataset("abisee/cnn_dailymail", "3.0.0", split="validation[:1%]")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-9D7B98BB - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/trainer/test_trainer_seq2seq.py:148`
- **数据流:** load_dataset() downloads dataset from Hugging Face Hub without specifying a revision.
- **判断理由:** Without revision pinning, the dataset could change unexpectedly, potentially affecting test reproducibility and introducing data integrity issues.

**代码片段:**
```
dataset = datasets.load_dataset("openai/gsm8k", "main", split="train[:38]")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-BF3F4D52 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/trainer/test_trainer_seq2seq.py:149`
- **数据流:** from_pretrained() downloads model from Hugging Face Hub without specifying a revision.
- **判断理由:** Without revision pinning, the downloaded model could change unexpectedly if the repository owner updates the default branch. This is a supply chain security risk.

**代码片段:**
```
model = AutoModelForSeq2SeqLM.from_pretrained("google-t5/t5-small")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-928EA8C0 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/trainer/test_trainer_seq2seq.py:150`
- **数据流:** from_pretrained() downloads tokenizer from Hugging Face Hub without specifying a revision.
- **判断理由:** Same supply chain risk as above - the tokenizer could change unexpectedly.

**代码片段:**
```
tokenizer = T5Tokenizer.from_pretrained("google-t5/t5-small")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-DEC5198D - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/trainer/test_trainer_seq2seq.py:152`
- **数据流:** from_pretrained() downloads generation config from Hugging Face Hub without specifying a revision.
- **判断理由:** Without revision pinning, the generation config could change unexpectedly, potentially affecting model behavior and test reproducibility.

**代码片段:**
```
gen_config = GenerationConfig.from_pretrained("google-t5/t5-small", max_length=None, min_length=None, max_new_tokens=256, min_new_tokens=1, num_beams=5)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-EEC352B6 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/trainer/test_trainer_seq2seq.py:190`
- **数据流:** from_pretrained() downloads model from Hugging Face Hub without specifying a revision.
- **判断理由:** Without revision pinning, the downloaded model could change unexpectedly if the repository owner updates the default branch. This is a supply chain security risk.

**代码片段:**
```
model = AutoModelForSeq2SeqLM.from_pretrained("google-t5/t5-small")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-E4CC1986 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/trainer/test_trainer_seq2seq.py:191`
- **数据流:** from_pretrained() downloads tokenizer from Hugging Face Hub without specifying a revision.
- **判断理由:** Same supply chain risk as above - the tokenizer could change unexpectedly.

**代码片段:**
```
tokenizer = T5Tokenizer.from_pretrained("google-t5/t5-small")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-CDBD6CC9 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_cache_utils.py:186`
- **数据流:** from_pretrained() called without specifying a 'revision' parameter, meaning the latest version of the model will be downloaded from Hugging Face Hub
- **判断理由:** Bandit B615: Downloading models from Hugging Face Hub without pinning a specific revision (commit hash, tag, or branch) means the code will always fetch the latest version. This is a supply chain security risk because if the upstream repository is compromised, the latest version could contain malicious code. The model could be replaced with a backdoored version without the user's knowledge.

**代码片段:**
```
AutoConfig.from_pretrained(
            "google/gemma-2b",
            torch_dtype=dtype,
            use_cache=True,
        )
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-94B08B29 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_cache_utils.py:191`
- **数据流:** from_pretrained() called without specifying a 'revision' parameter, meaning the latest version of the model will be downloaded from Hugging Face Hub
- **判断理由:** Bandit B615: Same vulnerability as above. The model is downloaded without pinning a specific revision, making it susceptible to supply chain attacks where a compromised upstream repository could serve malicious model weights.

**代码片段:**
```
m = AutoModelForCausalLM.from_pretrained(
            "google/gemma-2b",
            config=config,
            torch_dtype=dtype,
            attn_implementation="sdpa",
        ).to(device)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-18E0909D - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_cache_utils.py:197`
- **数据流:** from_pretrained() called without specifying a 'revision' parameter, meaning the latest version of the tokenizer will be downloaded from Hugging Face Hub
- **判断理由:** Bandit B615: Tokenizer downloaded without revision pinning. A compromised tokenizer could execute arbitrary code during tokenization or return malicious outputs.

**代码片段:**
```
tokenizer = AutoTokenizer.from_pretrained("google/gemma-2b")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-A759925B - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_cache_utils.py:238`
- **数据流:** from_pretrained() called without specifying a 'revision' parameter
- **判断理由:** Bandit B615: Same supply chain vulnerability as above.

**代码片段:**
```
AutoConfig.from_pretrained(
            "google/gemma-2b",
            torch_dtype=dtype,
            use_cache=True,
        )
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-769EFC32 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_cache_utils.py:239`
- **数据流:** from_pretrained() called without specifying a 'revision' parameter
- **判断理由:** Bandit B615: Same supply chain vulnerability as above.

**代码片段:**
```
m = AutoModelForCausalLM.from_pretrained(
            "google/gemma-2b",
            config=config,
            torch_dtype=dtype,
            attn_implementation="sdpa",
        ).to(device)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-1E826B01 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_cache_utils.py:267`
- **数据流:** from_pretrained() called without specifying a 'revision' parameter
- **判断理由:** Bandit B615: Same supply chain vulnerability as above.

**代码片段:**
```
AutoConfig.from_pretrained(
            "google/gemma-2b",
            torch_dtype=dtype,
            use_cache=True,
        )
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-E5265372 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_cache_utils.py:269`
- **数据流:** from_pretrained() called without specifying a 'revision' parameter
- **判断理由:** Bandit B615: Same supply chain vulnerability as above.

**代码片段:**
```
m = AutoModelForCausalLM.from_pretrained(
            "google/gemma-2b",
            config=config,
            torch_dtype=dtype,
            attn_implementation="sdpa",
        ).to(device)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-0550BBCB - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_cache_utils.py:282`
- **数据流:** from_pretrained() called without specifying a 'revision' parameter
- **判断理由:** Bandit B615: Same supply chain vulnerability as above.

**代码片段:**
```
AutoConfig.from_pretrained(
            "google/gemma-2b",
            torch_dtype=dtype,
            use_cache=True,
        )
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-226E5FA4 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_cache_utils.py:283`
- **数据流:** from_pretrained() called without specifying a 'revision' parameter
- **判断理由:** Bandit B615: Same supply chain vulnerability as above.

**代码片段:**
```
m = AutoModelForCausalLM.from_pretrained(
            "google/gemma-2b",
            config=config,
            torch_dtype=dtype,
            attn_implementation="sdpa",
        ).to(device)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-DAFB10BC - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_cache_utils.py:303`
- **数据流:** from_pretrained() called without specifying a 'revision' parameter
- **判断理由:** Bandit B615: Same supply chain vulnerability as above.

**代码片段:**
```
AutoConfig.from_pretrained(
            "google/gemma-2b",
            torch_dtype=dtype,
            use_cache=True,
        )
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-54282564 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_cache_utils.py:304`
- **数据流:** from_pretrained() called without specifying a 'revision' parameter
- **判断理由:** Bandit B615: Same supply chain vulnerability as above.

**代码片段:**
```
m = AutoModelForCausalLM.from_pretrained(
            "google/gemma-2b",
            config=config,
            torch_dtype=dtype,
            attn_implementation="sdpa",
        ).to(device)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-D054FEBE - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_cache_utils.py:328`
- **数据流:** from_pretrained() called without specifying a 'revision' parameter
- **判断理由:** Bandit B615: Same supply chain vulnerability as above.

**代码片段:**
```
AutoConfig.from_pretrained(
            "google/gemma-2b",
            torch_dtype=dtype,
            use_cache=True,
        )
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-28AF4241 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_cache_utils.py:329`
- **数据流:** from_pretrained() called without specifying a 'revision' parameter
- **判断理由:** Bandit B615: Same supply chain vulnerability as above.

**代码片段:**
```
m = AutoModelForCausalLM.from_pretrained(
            "google/gemma-2b",
            config=config,
            torch_dtype=dtype,
            attn_implementation="sdpa",
        ).to(device)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-8AAE99FC - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_cache_utils.py:342`
- **数据流:** from_pretrained() called without specifying a 'revision' parameter
- **判断理由:** Bandit B615: Same supply chain vulnerability as above.

**代码片段:**
```
AutoConfig.from_pretrained(
            "google/gemma-2b",
            torch_dtype=dtype,
            use_cache=True,
        )
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-CF3614CE - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_cache_utils.py:343`
- **数据流:** from_pretrained() called without specifying a 'revision' parameter
- **判断理由:** Bandit B615: Same supply chain vulnerability as above.

**代码片段:**
```
m = AutoModelForCausalLM.from_pretrained(
            "google/gemma-2b",
            config=config,
            torch_dtype=dtype,
            attn_implementation="sdpa",
        ).to(device)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-C385F5C0 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_cache_utils.py:390`
- **数据流:** from_pretrained() called without specifying a 'revision' parameter
- **判断理由:** Bandit B615: Same supply chain vulnerability as above.

**代码片段:**
```
AutoConfig.from_pretrained(
            "google/gemma-2b",
            torch_dtype=dtype,
            use_cache=True,
        )
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-77A9E5A8 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_cache_utils.py:393`
- **数据流:** from_pretrained() called without specifying a 'revision' parameter
- **判断理由:** Bandit B615: Same supply chain vulnerability as above.

**代码片段:**
```
m = AutoModelForCausalLM.from_pretrained(
            "google/gemma-2b",
            config=config,
            torch_dtype=dtype,
            attn_implementation="sdpa",
        ).to(device)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-3D9FC532 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_cache_utils.py:430`
- **数据流:** from_pretrained() called without specifying a 'revision' parameter
- **判断理由:** Bandit B615: Same supply chain vulnerability as above.

**代码片段:**
```
AutoConfig.from_pretrained(
            "google/gemma-2b",
            torch_dtype=dtype,
            use_cache=True,
        )
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-1BAB9393 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_cache_utils.py:433`
- **数据流:** from_pretrained() called without specifying a 'revision' parameter
- **判断理由:** Bandit B615: Same supply chain vulnerability as above.

**代码片段:**
```
m = AutoModelForCausalLM.from_pretrained(
            "google/gemma-2b",
            config=config,
            torch_dtype=dtype,
            attn_implementation="sdpa",
        ).to(device)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B7F02E53 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_cache_utils.py:482`
- **数据流:** from_pretrained() called without specifying a 'revision' parameter
- **判断理由:** Bandit B615: Same supply chain vulnerability as above.

**代码片段:**
```
AutoConfig.from_pretrained(
            "google/gemma-2b",
            torch_dtype=dtype,
            use_cache=True,
        )
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-0657D7CC - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_cache_utils.py:485`
- **数据流:** from_pretrained() called without specifying a 'revision' parameter
- **判断理由:** Bandit B615: Same supply chain vulnerability as above.

**代码片段:**
```
m = AutoModelForCausalLM.from_pretrained(
            "google/gemma-2b",
            config=config,
            torch_dtype=dtype,
            attn_implementation="sdpa",
        ).to(device)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-AA803AB4 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_cache_utils.py:516`
- **数据流:** from_pretrained() called without specifying a 'revision' parameter
- **判断理由:** Bandit B615: Same supply chain vulnerability as above.

**代码片段:**
```
AutoConfig.from_pretrained(
            "google/gemma-2b",
            torch_dtype=dtype,
            use_cache=True,
        )
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-DC244872 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_cache_utils.py:519`
- **数据流:** from_pretrained() called without specifying a 'revision' parameter
- **判断理由:** Bandit B615: Same supply chain vulnerability as above.

**代码片段:**
```
m = AutoModelForCausalLM.from_pretrained(
            "google/gemma-2b",
            config=config,
            torch_dtype=dtype,
            attn_implementation="sdpa",
        ).to(device)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-48C6CC00 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_cache_utils.py:553`
- **数据流:** from_pretrained() called without specifying a 'revision' parameter
- **判断理由:** Bandit B615: Same supply chain vulnerability as above.

**代码片段:**
```
AutoConfig.from_pretrained(
            "google/gemma-2b",
            torch_dtype=dtype,
            use_cache=True,
        )
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-E8412972 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_cache_utils.py:554`
- **数据流:** from_pretrained() called without specifying a 'revision' parameter
- **判断理由:** Bandit B615: Same supply chain vulnerability as above.

**代码片段:**
```
m = AutoModelForCausalLM.from_pretrained(
            "google/gemma-2b",
            config=config,
            torch_dtype=dtype,
            attn_implementation="sdpa",
        ).to(device)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-E00AF8D2 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_cache_utils.py:577`
- **数据流:** from_pretrained() called without specifying a 'revision' parameter
- **判断理由:** Bandit B615: Same supply chain vulnerability as above.

**代码片段:**
```
AutoConfig.from_pretrained(
            "google/gemma-2b",
            torch_dtype=dtype,
            use_cache=True,
        )
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-7AEA93C2 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_cache_utils.py:578`
- **数据流:** from_pretrained() called without specifying a 'revision' parameter
- **判断理由:** Bandit B615: Same supply chain vulnerability as above.

**代码片段:**
```
m = AutoModelForCausalLM.from_pretrained(
            "google/gemma-2b",
            config=config,
            torch_dtype=dtype,
            attn_implementation="sdpa",
        ).to(device)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-63A26968 - 不安全的临时文件/目录使用

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_cli.py:43`
- **数据流:** 硬编码路径 /tmp/hf-internal-testing/tiny-random-gptj 被直接用于文件删除操作
- **判断理由:** 代码直接使用硬编码的 /tmp 路径进行文件操作，没有使用安全的临时文件创建方法（如 tempfile.mkdtemp()）。在共享的 /tmp 目录下操作可能导致竞态条件攻击（symlink attack），攻击者可以预测路径并创建符号链接指向其他文件，导致意外删除或覆盖系统文件。

**代码片段:**
```
shutil.rmtree("/tmp/hf-internal-testing/tiny-random-gptj", ignore_errors=True)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-93A60EEE - 不安全的临时文件/目录使用

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_cli.py:46`
- **数据流:** 硬编码路径 /tmp/hf-internal-testing/tiny-random-gptj/tf_model.h5 被用于文件存在性检查
- **判断理由:** 在共享的 /tmp 目录下使用硬编码路径进行文件操作，存在安全风险。攻击者可能通过创建恶意符号链接来干扰测试结果或导致信息泄露。

**代码片段:**
```
self.assertTrue(os.path.exists("/tmp/hf-internal-testing/tiny-random-gptj/tf_model.h5"))
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-DF585DD8 - 不安全的临时文件/目录使用

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_cli.py:54`
- **数据流:** 硬编码路径 /tmp/models--hf-internal-testing--tiny-random-gptj 被直接用于文件删除操作
- **判断理由:** 同样使用硬编码的 /tmp 路径进行递归删除操作，存在符号链接攻击风险。攻击者可以预先创建同名符号链接指向敏感文件，导致测试执行时意外删除重要文件。

**代码片段:**
```
shutil.rmtree("/tmp/models--hf-internal-testing--tiny-random-gptj", ignore_errors=True)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-08E0848D - 不安全的临时文件/目录使用

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_cli.py:60`
- **数据流:** 硬编码路径 /tmp/models--hf-internal-testing--tiny-random-gptj/blobs 被用于文件存在性检查
- **判断理由:** 在共享临时目录中使用可预测路径，存在被攻击者预创建恶意文件的风险。

**代码片段:**
```
self.assertTrue(os.path.exists("/tmp/models--hf-internal-testing--tiny-random-gptj/blobs"))
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-FF80738F - 不安全的临时文件/目录使用

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_cli.py:61`
- **数据流:** 硬编码路径 /tmp/models--hf-internal-testing--tiny-random-gptj/refs 被用于文件存在性检查
- **判断理由:** 同上，使用可预测的临时目录路径进行文件操作。

**代码片段:**
```
self.assertTrue(os.path.exists("/tmp/models--hf-internal-testing--tiny-random-gptj/refs"))
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-E4840F8F - 不安全的临时文件/目录使用

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_cli.py:62`
- **数据流:** 硬编码路径 /tmp/models--hf-internal-testing--tiny-random-gptj/snapshots 被用于文件存在性检查
- **判断理由:** 同上，使用可预测的临时目录路径进行文件操作。

**代码片段:**
```
self.assertTrue(os.path.exists("/tmp/models--hf-internal-testing--tiny-random-gptj/snapshots"))
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-5BC2F9A8 - 不安全的临时文件/目录使用

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_cli.py:49`
- **数据流:** 硬编码路径 /tmp/hf-internal-testing/tiny-random-gptj 被直接用于文件删除操作
- **判断理由:** 与第43行相同的漏洞，在测试清理阶段使用硬编码的临时路径进行递归删除。

**代码片段:**
```
shutil.rmtree("/tmp/hf-internal-testing/tiny-random-gptj", ignore_errors=True)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-DA537426 - 不安全的临时文件/目录使用

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_cli.py:80`
- **数据流:** 硬编码路径 /tmp/models--hf-internal-testing--test_dynamic_model_with_tokenizer 被直接用于文件删除操作
- **判断理由:** 在另一个测试函数中同样使用硬编码的 /tmp 路径进行递归删除操作，存在相同的符号链接攻击风险。

**代码片段:**
```
shutil.rmtree("/tmp/models--hf-internal-testing--test_dynamic_model_with_tokenizer", ignore_errors=True)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-0619851A - 不安全的临时文件/目录使用

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_cli.py:86`
- **数据流:** 硬编码路径 /tmp/models--hf-internal-testing--test_dynamic_model_with_tokenizer/blobs 被用于文件存在性检查
- **判断理由:** 在共享临时目录中使用可预测路径进行文件存在性检查。

**代码片段:**
```
self.assertTrue(os.path.exists("/tmp/models--hf-internal-testing--test_dynamic_model_with_tokenizer/blobs"))
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-1B794F89 - 不安全的临时文件/目录使用

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_cli.py:87`
- **数据流:** 硬编码路径 /tmp/models--hf-internal-testing--test_dynamic_model_with_tokenizer/refs 被用于文件存在性检查
- **判断理由:** 同上，使用可预测的临时目录路径进行文件操作。

**代码片段:**
```
self.assertTrue(os.path.exists("/tmp/models--hf-internal-testing--test_dynamic_model_with_tokenizer/refs"))
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-76C4838D - 不安全的临时文件/目录使用

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_cli.py:89`
- **数据流:** 硬编码路径 /tmp/models--hf-internal-testing--test_dynamic_model_with_tokenizer/snapshots 被用于文件存在性检查
- **判断理由:** 同上，使用可预测的临时目录路径进行文件操作。

**代码片段:**
```
self.assertTrue(os.path.exists("/tmp/models--hf-internal-testing--test_dynamic_model_with_tokenizer/snapshots"))
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-9E5F864A - 不安全的临时文件/目录使用

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_cli.py:73`
- **数据流:** 硬编码路径 /tmp/models--hf-internal-testing--tiny-random-gptj 被直接用于文件删除操作
- **判断理由:** 与第54行相同的漏洞，在另一个测试函数中重复使用相同的硬编码临时路径进行递归删除。

**代码片段:**
```
shutil.rmtree("/tmp/models--hf-internal-testing--tiny-random-gptj", ignore_errors=True)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-7C7BAC73 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_configuration_utils.py:119`
- **数据流:** 用户控制的仓库名称(tmp_repo)通过from_pretrained()下载模型配置，未指定revision参数，可能下载到恶意版本
- **判断理由:** from_pretrained()调用未指定revision参数，默认使用最新版本。攻击者可能上传恶意版本到同一仓库，导致供应链攻击。虽然这是测试代码，但该模式在生产环境中存在风险。

**代码片段:**
```
new_config = BertConfig.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-C2EED995 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_configuration_utils.py:138`
- **数据流:** 用户控制的仓库名称(tmp_repo)通过from_pretrained()下载模型配置，未指定revision参数
- **判断理由:** 与line 119相同的问题，在test_push_to_hub_via_save_pretrained方法中未指定revision参数

**代码片段:**
```
new_config = BertConfig.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-7C17B173 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_configuration_utils.py:155`
- **数据流:** 用户控制的仓库名称(tmp_repo)通过from_pretrained()下载模型配置，未指定revision参数
- **判断理由:** 在test_push_to_hub_in_organization方法中未指定revision参数

**代码片段:**
```
new_config = BertConfig.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-BB3FAAF8 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_configuration_utils.py:173`
- **数据流:** 用户控制的仓库名称(tmp_repo)通过from_pretrained()下载模型配置，未指定revision参数
- **判断理由:** 在test_push_to_hub_in_organization_via_save_pretrained方法中未指定revision参数

**代码片段:**
```
new_config = BertConfig.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-AC56C7E9 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_configuration_utils.py:194`
- **数据流:** 用户控制的仓库名称(tmp_repo)通过from_pretrained()下载模型配置，且trust_remote_code=True，未指定revision参数
- **判断理由:** 在test_push_to_hub_dynamic_config方法中，不仅未指定revision参数，还设置了trust_remote_code=True，增加了远程代码执行的风险

**代码片段:**
```
new_config = AutoConfig.from_pretrained(tmp_repo, trust_remote_code=True)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-8CE63E8A - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_configuration_utils.py:243`
- **数据流:** 用户控制的仓库名称(tmp_repo)通过from_pretrained()下载模型配置，未指定revision参数
- **判断理由:** 在ConfigTestUtils类的测试方法中未指定revision参数

**代码片段:**
```
new_config = BertConfig.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-E3E125A9 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_configuration_utils.py:252`
- **数据流:** 用户控制的仓库名称(tmp_repo)通过from_pretrained()下载模型配置，未指定revision参数
- **判断理由:** 未指定revision参数

**代码片段:**
```
new_config = BertConfig.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-52B0DCE7 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_configuration_utils.py:254`
- **数据流:** 用户控制的仓库名称(tmp_repo)通过from_pretrained()下载模型配置，未指定revision参数
- **判断理由:** 未指定revision参数

**代码片段:**
```
new_config = BertConfig.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-9BA00A25 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_configuration_utils.py:267`
- **数据流:** 用户控制的仓库名称(tmp_repo)通过from_pretrained()下载模型配置，未指定revision参数
- **判断理由:** 未指定revision参数

**代码片段:**
```
new_config = BertConfig.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-C56FACB5 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_configuration_utils.py:271`
- **数据流:** 用户控制的仓库名称(tmp_repo)通过from_pretrained()下载模型配置，未指定revision参数
- **判断理由:** 未指定revision参数

**代码片段:**
```
new_config = BertConfig.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-6D016CAA - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_configuration_utils.py:276`
- **数据流:** 用户控制的仓库名称(tmp_repo)通过from_pretrained()下载模型配置，未指定revision参数
- **判断理由:** 未指定revision参数

**代码片段:**
```
new_config = BertConfig.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-AC4D74FD - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_configuration_utils.py:285`
- **数据流:** 用户控制的仓库名称(tmp_repo)通过from_pretrained()下载模型配置，未指定revision参数
- **判断理由:** 未指定revision参数

**代码片段:**
```
new_config = BertConfig.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-923BC3C9 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_configuration_utils.py:294`
- **数据流:** 用户控制的仓库名称(tmp_repo)通过from_pretrained()下载模型配置，未指定revision参数
- **判断理由:** 未指定revision参数

**代码片段:**
```
new_config = BertConfig.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-11CCE5B5 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_configuration_utils.py:304`
- **数据流:** 用户控制的仓库名称(tmp_repo)通过from_pretrained()下载模型配置，未指定revision参数
- **判断理由:** 未指定revision参数

**代码片段:**
```
new_config = BertConfig.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-3FB050C6 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_configuration_utils.py:315`
- **数据流:** 用户控制的仓库名称(tmp_repo)通过from_pretrained()下载模型配置，未指定revision参数
- **判断理由:** 未指定revision参数

**代码片段:**
```
new_config = BertConfig.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-E89BFA19 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_configuration_utils.py:339`
- **数据流:** 用户控制的仓库名称(tmp_repo)通过from_pretrained()下载模型配置，未指定revision参数
- **判断理由:** 未指定revision参数

**代码片段:**
```
new_config = BertConfig.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-6F5FDF09 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests\utils\test_feature_extraction_utils.py:48`
- **数据流:** Hardcoded model ID -> from_pretrained() -> Hugging Face Hub download (no revision specified)
- **判断理由:** from_pretrained() is called without specifying a revision parameter, meaning the latest version of the model will be downloaded. This could lead to supply chain attacks if the model repository is compromised and a malicious version is pushed.

**代码片段:**
```
_ = Wav2Vec2FeatureExtractor.from_pretrained("hf-internal-testing/tiny-random-wav2vec2")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-1E4DCED9 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests\utils\test_feature_extraction_utils.py:51`
- **数据流:** Hardcoded model ID -> from_pretrained() -> Hugging Face Hub download (no revision specified)
- **判断理由:** Same as line 48. The second call to from_pretrained() in the same test also lacks revision pinning.

**代码片段:**
```
_ = Wav2Vec2FeatureExtractor.from_pretrained("hf-internal-testing/tiny-random-wav2vec2")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-3C1B0324 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests\utils\test_feature_extraction_utils.py:76`
- **数据流:** Local directory path -> from_pretrained() -> local file loading (no revision parameter)
- **判断理由:** While this call uses a local directory path (SAMPLE_FEATURE_EXTRACTION_CONFIG_DIR), the from_pretrained() method could potentially fall back to Hub download if the local path is invalid. No revision is pinned.

**代码片段:**
```
feature_extractor = Wav2Vec2FeatureExtractor.from_pretrained(SAMPLE_FEATURE_EXTRACTION_CONFIG_DIR)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-9424B291 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests\utils\test_feature_extraction_utils.py:79`
- **数据流:** Dynamic repo name (tmp_repo) -> from_pretrained() -> Hugging Face Hub download (no revision specified)
- **判断理由:** from_pretrained() is called with a dynamically generated repository name without specifying a revision. This could download unexpected versions if the repository has been updated.

**代码片段:**
```
new_feature_extractor = Wav2Vec2FeatureExtractor.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-C0700C6C - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests\utils\test_feature_extraction_utils.py:90`
- **数据流:** Local directory path -> from_pretrained() -> local file loading (no revision parameter)
- **判断理由:** Same as line 76. Uses local directory but no revision pinning.

**代码片段:**
```
feature_extractor = Wav2Vec2FeatureExtractor.from_pretrained(SAMPLE_FEATURE_EXTRACTION_CONFIG_DIR)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-E2520532 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests\utils\test_feature_extraction_utils.py:94`
- **数据流:** Dynamic repo name (tmp_repo) -> from_pretrained() -> Hugging Face Hub download (no revision specified)
- **判断理由:** Same as line 79. Dynamic repo name without revision pinning.

**代码片段:**
```
new_feature_extractor = Wav2Vec2FeatureExtractor.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-06D6E39A - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests\utils\test_feature_extraction_utils.py:105`
- **数据流:** Local directory path -> from_pretrained() -> local file loading (no revision parameter)
- **判断理由:** Same as line 76. Uses local directory but no revision pinning.

**代码片段:**
```
feature_extractor = Wav2Vec2FeatureExtractor.from_pretrained(SAMPLE_FEATURE_EXTRACTION_CONFIG_DIR)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-DFEFB7A8 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests\utils\test_feature_extraction_utils.py:108`
- **数据流:** Dynamic repo name (tmp_repo) -> from_pretrained() -> Hugging Face Hub download (no revision specified)
- **判断理由:** Same as line 79. Dynamic repo name without revision pinning.

**代码片段:**
```
new_feature_extractor = Wav2Vec2FeatureExtractor.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-87B61D0D - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests\utils\test_feature_extraction_utils.py:119`
- **数据流:** Local directory path -> from_pretrained() -> local file loading (no revision parameter)
- **判断理由:** Same as line 76. Uses local directory but no revision pinning.

**代码片段:**
```
feature_extractor = Wav2Vec2FeatureExtractor.from_pretrained(SAMPLE_FEATURE_EXTRACTION_CONFIG_DIR)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-D25F5F62 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests\utils\test_feature_extraction_utils.py:123`
- **数据流:** Dynamic repo name (tmp_repo) -> from_pretrained() -> Hugging Face Hub download (no revision specified)
- **判断理由:** Same as line 79. Dynamic repo name without revision pinning.

**代码片段:**
```
new_feature_extractor = Wav2Vec2FeatureExtractor.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-8F944E4E - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests\utils\test_feature_extraction_utils.py:145`
- **数据流:** Dynamic repo name (tmp_repo) -> AutoFeatureExtractor.from_pretrained() -> Hugging Face Hub download (no revision specified, trust_remote_code=True)
- **判断理由:** This is the most critical instance. from_pretrained() is called with trust_remote_code=True, which allows arbitrary code execution from the downloaded model. Combined with no revision pinning, this creates a significant supply chain risk if the repository is compromised.

**代码片段:**
```
new_feature_extractor = AutoFeatureExtractor.from_pretrained(tmp_repo, trust_remote_code=True)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-BF2D2795 - 不安全的Hugging Face Hub下载（无修订版本锁定）

- **严重等级:** MEDIUM
- **文件位置:** `tests\utils\test_hub_utils.py:114`
- **数据流:** 用户输入TINY_BERT_PT_ONLY和WEIGHTS_NAME作为参数传递给hf_hub_download函数，未指定revision参数，导致下载的模型文件可能被恶意更新
- **判断理由:** hf_hub_download调用未指定revision参数，这意味着每次下载都会获取最新版本。如果模型仓库被恶意更新，测试将下载并缓存恶意文件。虽然这是测试代码，但可能影响CI/CD环境的安全性。bandit工具已标记此问题为B615。

**代码片段:**
```
hf_hub_download(TINY_BERT_PT_ONLY, WEIGHTS_NAME, cache_dir=tmp_dir)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-4EE47951 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_image_processing_utils.py:48`
- **数据流:** 静态字符串常量作为模型ID传递给from_pretrained()，未指定revision参数
- **判断理由:** from_pretrained()调用未指定revision参数，将下载最新版本的模型。如果模型仓库被恶意更新，可能导致下载恶意模型。虽然这是测试代码，但最佳实践应固定revision以确保可复现性和安全性。

**代码片段:**
```
_ = ViTImageProcessor.from_pretrained("hf-internal-testing/tiny-random-vit")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-879D9340 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_image_processing_utils.py:51`
- **数据流:** 静态字符串常量作为模型ID传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，第二次调用from_pretrained()同样未指定revision参数。

**代码片段:**
```
_ = ViTImageProcessor.from_pretrained("hf-internal-testing/tiny-random-vit")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-6DCD3C64 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_image_processing_utils.py:58`
- **数据流:** 静态字符串常量作为模型ID传递给from_pretrained()，未指定revision参数
- **判断理由:** AutoImageProcessor.from_pretrained()调用未指定revision参数。

**代码片段:**
```
_ = AutoImageProcessor.from_pretrained("hf-internal-testing/stable-diffusion-all-variants")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-1CD5659F - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_image_processing_utils.py:60`
- **数据流:** 静态字符串常量作为模型ID传递给from_pretrained()，指定了subfolder但未指定revision参数
- **判断理由:** 虽然指定了subfolder参数，但未指定revision参数，仍存在下载未固定版本模型的风险。

**代码片段:**
```
config = AutoImageProcessor.from_pretrained(
    "hf-internal-testing/stable-diffusion-all-variants", subfolder="feature_extractor"
)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-ACDCDAA7 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_image_processing_utils.py:86`
- **数据流:** 动态生成的repo ID传递给from_pretrained()，未指定revision参数
- **判断理由:** from_pretrained()调用未指定revision参数，虽然repo是动态创建的，但最佳实践应固定revision。

**代码片段:**
```
new_image_processor = ViTImageProcessor.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-60466197 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_image_processing_utils.py:89`
- **数据流:** 动态生成的repo ID传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，未指定revision参数。

**代码片段:**
```
new_image_processor = ViTImageProcessor.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-44A5D8C0 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_image_processing_utils.py:100`
- **数据流:** 动态生成的repo ID传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，未指定revision参数。

**代码片段:**
```
new_image_processor = ViTImageProcessor.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-78681CBE - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_image_processing_utils.py:104`
- **数据流:** 动态生成的repo ID传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，未指定revision参数。

**代码片段:**
```
new_image_processor = ViTImageProcessor.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-543554DD - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_image_processing_utils.py:115`
- **数据流:** 动态生成的repo ID传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，未指定revision参数。

**代码片段:**
```
new_image_processor = ViTImageProcessor.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-ABC1CBDF - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_image_processing_utils.py:118`
- **数据流:** 动态生成的repo ID传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，未指定revision参数。

**代码片段:**
```
new_image_processor = ViTImageProcessor.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-7051EBAF - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_image_processing_utils.py:129`
- **数据流:** 动态生成的repo ID传递给from_pretrained()，未指定revision参数，且启用了trust_remote_code
- **判断理由:** 未指定revision参数且启用了trust_remote_code=True，增加了安全风险。如果模型仓库被恶意更新，可能执行任意代码。

**代码片段:**
```
new_image_processor = AutoImageProcessor.from_pretrained(tmp_repo, trust_remote_code=True)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-CC9680E5 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_image_processing_utils.py:133`
- **数据流:** 动态生成的repo ID传递给from_pretrained()，未指定revision参数，且启用了trust_remote_code
- **判断理由:** 同上，未指定revision参数且启用了trust_remote_code=True。

**代码片段:**
```
new_image_processor = AutoImageProcessor.from_pretrained(tmp_repo, trust_remote_code=True)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-A01340E5 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_image_processing_utils.py:155`
- **数据流:** 动态生成的repo ID传递给from_pretrained()，未指定revision参数，且启用了trust_remote_code
- **判断理由:** 同上，未指定revision参数且启用了trust_remote_code=True。

**代码片段:**
```
new_image_processor = AutoImageProcessor.from_pretrained(tmp_repo, trust_remote_code=True)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-9FB4DE3F - SSRF (Server-Side Request Forgery) / Missing Request Timeout

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_image_utils.py:47`
- **数据流:** 用户控制的URL参数(url)通过hf_hub_url函数生成，直接传递给requests.get()，没有设置timeout参数
- **判断理由:** requests.get()调用没有设置timeout参数，可能导致请求被挂起或阻塞。虽然这是测试代码，但该函数get_image_from_hub_dataset可能被其他模块调用。缺少timeout会导致：1) 请求可能无限期等待，造成资源耗尽；2) 如果URL指向内部服务，可能被利用进行SSRF攻击。建议添加timeout参数如timeout=10

**代码片段:**
```
return PIL.Image.open(BytesIO(requests.get(url).content))
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-68412BF7 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:76`
- **数据流:** 用户控制的repo名称(tmp_repo)直接传递给from_pretrained()，未指定revision参数，默认使用最新版本
- **判断理由:** from_pretrained()调用未指定revision参数，会下载最新版本的模型。如果攻击者能够控制或污染该仓库，可以推送恶意版本，导致下载执行恶意代码。测试代码中tmp_repo由USER和临时目录名拼接而成，虽然当前是测试环境，但该模式若被复制到生产代码将构成严重风险。

**代码片段:**
```
new_model = FlaxBertModel.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-FD9D0ABA - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:99`
- **数据流:** 用户控制的repo名称(tmp_repo)直接传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()调用未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
new_model = FlaxBertModel.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-F916C738 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:121`
- **数据流:** 用户控制的repo名称(tmp_repo)直接传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()调用未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
new_model = FlaxBertModel.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-9C7766E6 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:144`
- **数据流:** 用户控制的repo名称(tmp_repo)直接传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()调用未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
new_model = FlaxBertModel.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B9FF697D - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:171`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 虽然使用的是本地目录，但from_pretrained()在本地找不到模型时会回退到Hub下载，且未指定revision参数，存在潜在风险。

**代码片段:**
```
model_loaded = FlaxBertModel.from_pretrained(tmp_dir, subfolder=subfolder)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B64DAD2F - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:179`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
_ = FlaxBertModel.from_pretrained(tmp_dir)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-803538B4 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:181`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
model_loaded = FlaxBertModel.from_pretrained(tmp_dir, subfolder=subfolder)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-AAA76528 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:186`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
model_loaded = FlaxBertModel.from_pretrained(tmp_dir, subfolder=subfolder)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-18572B18 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:194`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
_ = FlaxBertModel.from_pretrained(tmp_dir)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-09A1BB8E - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:196`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
model_loaded = FlaxBertModel.from_pretrained(tmp_dir, subfolder=subfolder)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-4582AC29 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:205`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
_ = FlaxBertModel.from_pretrained(tmp_dir)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-E6A49FEE - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:207`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
model_loaded = FlaxBertModel.from_pretrained(tmp_dir, subfolder=subfolder)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-E7E96D3C - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:215`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
_ = FlaxBertModel.from_pretrained(tmp_dir)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-6CA7CDF4 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:217`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
model_loaded = FlaxBertModel.from_pretrained(tmp_dir, subfolder=subfolder)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-CF85A46C - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:223`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
model_loaded = FlaxBertModel.from_pretrained(tmp_dir, subfolder=subfolder)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-1AC5A299 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:231`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
model_loaded = FlaxBertModel.from_pretrained(tmp_dir, subfolder=subfolder)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-6D74F1A3 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:239`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
_ = FlaxBertModel.from_pretrained(tmp_dir)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-D0381C70 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:240`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
model_loaded = FlaxBertModel.from_pretrained(tmp_dir, subfolder=subfolder)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-750360B1 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:247`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
model_loaded = FlaxBertModel.from_pretrained(tmp_dir, subfolder=subfolder)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-BE3182D6 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:257`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
_ = FlaxBertModel.from_pretrained(tmp_dir)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-A14BA1E8 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:260`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
model_loaded = FlaxBertModel.from_pretrained(tmp_dir, subfolder=subfolder)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-349A1FFB - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:269`
- **数据流:** 用户控制的model_id传递给snapshot_download()，未指定revision参数
- **判断理由:** snapshot_download()调用未指定revision参数，会下载最新版本的仓库快照。如果攻击者能够控制该仓库，可以推送恶意版本，导致下载恶意文件。

**代码片段:**
```
snapshot_download(repo_id=model_id, allow_patterns=SAFE_WEIGHTS_NAME)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-8A10F43D - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:270`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
_ = FlaxBertModel.from_pretrained(tmp_dir, subfolder=subfolder)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-7F44CE96 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:273`
- **数据流:** 用户控制的model_id传递给snapshot_download()，未指定revision参数
- **判断理由:** 同上，snapshot_download()调用未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
snapshot_download(repo_id=model_id, allow_patterns=SAFE_WEIGHTS_NAME)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-42A849AC - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:274`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
_ = FlaxBertModel.from_pretrained(tmp_dir, subfolder=subfolder)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-880C8505 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:285`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
_ = FlaxBertModel.from_pretrained(tmp_dir)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-2DA09676 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:288`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
model_loaded = FlaxBertModel.from_pretrained(tmp_dir, subfolder=subfolder)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-DDE9452C - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:301`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
_ = FlaxBertModel.from_pretrained(tmp_dir)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-2B443280 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:306`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
_ = FlaxBertModel.from_pretrained(tmp_dir)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-8AB50019 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:309`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
model_loaded = FlaxBertModel.from_pretrained(tmp_dir, subfolder=subfolder)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-05189E74 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:320`
- **数据流:** 用户控制的model_id传递给snapshot_download()，未指定revision参数
- **判断理由:** 同上，snapshot_download()调用未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
snapshot_download(repo_id=model_id, allow_patterns=SAFE_WEIGHTS_NAME)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-C5ED75CD - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:321`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
_ = FlaxBertModel.from_pretrained(tmp_dir, subfolder=subfolder)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-09F11A1C - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:325`
- **数据流:** 用户控制的model_id传递给snapshot_download()，未指定revision参数
- **判断理由:** 同上，snapshot_download()调用未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
snapshot_download(repo_id=model_id, allow_patterns=SAFE_WEIGHTS_NAME)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B45254CE - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:326`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
_ = FlaxBertModel.from_pretrained(tmp_dir, subfolder=subfolder)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-82AF04F9 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:336`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
_ = FlaxBertModel.from_pretrained(tmp_dir)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-70817562 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:345`
- **数据流:** 用户控制的model_id传递给snapshot_download()，未指定revision参数
- **判断理由:** 同上，snapshot_download()调用未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
snapshot_download(repo_id=model_id, allow_patterns=SAFE_WEIGHTS_NAME)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-53BA8568 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:346`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
_ = FlaxBertModel.from_pretrained(tmp_dir, subfolder=subfolder)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-A977C9BF - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:350`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
_ = FlaxBertModel.from_pretrained(tmp_dir)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-76771323 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:354`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
_ = FlaxBertModel.from_pretrained(tmp_dir)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-A9427D29 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:362`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
_ = FlaxBertModel.from_pretrained(tmp_dir)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-1A84702D - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:363`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
_ = FlaxBertModel.from_pretrained(tmp_dir)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-AF30901A - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:367`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
_ = FlaxBertModel.from_pretrained(tmp_dir)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-1D405CDE - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:374`
- **数据流:** 用户控制的model_id传递给snapshot_download()，未指定revision参数
- **判断理由:** 同上，snapshot_download()调用未指定revision参数，存在供应链攻击风险。

**代码片段:**
```
snapshot_download(repo_id=model_id, allow_patterns=SAFE_WEIGHTS_NAME)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-130DAE27 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:379`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
_ = FlaxBertModel.from_pretrained(tmp_dir)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-EB222B47 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:385`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
_ = FlaxBertModel.from_pretrained(tmp_dir)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-EC7A5E59 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:394`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
_ = FlaxBertModel.from_pretrained(tmp_dir)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-41BB0671 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:405`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
_ = FlaxBertModel.from_pretrained(tmp_dir)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-8C6709D9 - Unsafe Hugging Face Hub Download Without Revision Pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_flax_utils.py:414`
- **数据流:** 本地目录路径(tmp_dir)传递给from_pretrained()，未指定revision参数
- **判断理由:** 同上，from_pretrained()可能回退到Hub下载，未指定revision参数。

**代码片段:**
```
_ = FlaxBertModel.from_pretrained(tmp_dir)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-80D28135 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_tf_utils.py:108`
- **数据流:** from_pretrained() is called without specifying a revision parameter, which means it will download the latest version of the model from Hugging Face Hub. This could lead to supply chain attacks if the repository is compromised.
- **判断理由:** The from_pretrained() method is called without a 'revision' parameter. Without pinning to a specific commit hash or tag, the code will always download the latest version of the model. If an attacker compromises the repository and uploads a malicious model, the code would automatically download and load it, potentially executing arbitrary code or leaking sensitive data.

**代码片段:**
```
_ = TFBertModel.from_pretrained("hf-internal-testing/tiny-random-bert")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-CC655EF3 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_tf_utils.py:112`
- **数据流:** from_pretrained() is called without specifying a revision parameter, which means it will download the latest version of the model from Hugging Face Hub.
- **判断理由:** Same vulnerability as line 108. The from_pretrained() call does not pin to a specific revision, making it vulnerable to supply chain attacks.

**代码片段:**
```
_ = TFBertModel.from_pretrained("hf-internal-testing/tiny-random-bert")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-515E8A75 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_modeling_tf_utils.py:226`
- **数据流:** Multiple from_pretrained() calls throughout the file without specifying revision parameter
- **判断理由:** All instances of from_pretrained() and snapshot_download() calls in this file (lines 108, 112, 226, 228, 233, 234, 242, 248, 250, 256, 259, 266, 268, 341, 342, 347, 353, 393, 402, 432, 444, 445, 452, 493, 502, 510, 519, 527, 528, 534, 542, 543, 549, 557, 560, 567, 575, 579, 587, 588, 592, 600, 603, 608, 610, 618, 619, 622, 623, 634, 637, 648, 649, 653, 654, 665, 674, 675, 713, 738, 767, 797, 822) are missing the 'revision' parameter. This is a systematic issue throughout the test file where model downloads are not pinned to specific versions, creating a supply chain security risk.

**代码片段:**
```
from_pretrained() calls without revision parameter
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-E98F267D - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests/utils/test_model_card.py:82`
- **数据流:** 用户输入(测试数据) -> ModelCard.from_pretrained() -> 从Hugging Face Hub下载模型卡，未指定revision参数
- **判断理由:** ModelCard.from_pretrained()方法在未指定revision参数时，会从Hugging Face Hub下载最新版本的模型卡。这可能导致下载到被恶意篡改的版本，存在供应链攻击风险。虽然这是测试代码，但该模式可能被复制到生产代码中。建议始终指定具体的revision版本号以确保下载内容的完整性。

**代码片段:**
```
model_card_second = ModelCard.from_pretrained(tmpdirname)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-142A4EDE - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests\utils\test_offline.py:54`
- **数据流:** mname = "hf-internal-testing/tiny-random-bert" → BertConfig.from_pretrained(mname) (line 54)
- **判断理由:** 调用 from_pretrained() 时未指定 revision 参数，可能导致下载未固定版本的模型文件。在测试环境中，这可能导致测试结果不一致或引入恶意模型。虽然这是测试代码，但未固定版本仍存在供应链攻击风险。

**代码片段:**
```
BertConfig.from_pretrained(mname)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-39D8EF62 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests\utils\test_offline.py:55`
- **数据流:** mname = "hf-internal-testing/tiny-random-bert" → BertModel.from_pretrained(mname) (line 55)
- **判断理由:** 同上，BertModel.from_pretrained() 未指定 revision 参数，存在相同风险。

**代码片段:**
```
BertModel.from_pretrained(mname)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-3ADAA59B - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests\utils\test_offline.py:56`
- **数据流:** mname = "hf-internal-testing/tiny-random-bert" → BertTokenizer.from_pretrained(mname) (line 56)
- **判断理由:** 同上，BertTokenizer.from_pretrained() 未指定 revision 参数，存在相同风险。

**代码片段:**
```
BertTokenizer.from_pretrained(mname)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-8BE529B8 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests\utils\test_offline.py:89`
- **数据流:** mname = "hf-internal-testing/tiny-random-bert" → BertConfig.from_pretrained(mname) (line 89)
- **判断理由:** 在 test_offline_mode_no_internet 测试方法中，同样未指定 revision 参数，存在相同风险。

**代码片段:**
```
BertConfig.from_pretrained(mname)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-83C68D4E - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests\utils\test_offline.py:90`
- **数据流:** mname = "hf-internal-testing/tiny-random-bert" → BertModel.from_pretrained(mname) (line 90)
- **判断理由:** 同上，BertModel.from_pretrained() 未指定 revision 参数。

**代码片段:**
```
BertModel.from_pretrained(mname)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-A26B2A92 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** MEDIUM
- **文件位置:** `tests\utils\test_offline.py:91`
- **数据流:** mname = "hf-internal-testing/tiny-random-bert" → BertTokenizer.from_pretrained(mname) (line 91)
- **判断理由:** 同上，BertTokenizer.from_pretrained() 未指定 revision 参数。

**代码片段:**
```
BertTokenizer.from_pretrained(mname)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B480F10E - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_tokenization_utils.py:58`
- **数据流:** from_pretrained() downloads model from Hugging Face Hub without specifying a revision/tag/commit hash
- **判断理由:** Bandit B615: Using from_pretrained() without revision pinning allows downloading arbitrary versions of the model, which could be compromised by an attacker who gains access to the repository. This is a supply chain security risk.

**代码片段:**
```
_ = BertTokenizer.from_pretrained("hf-internal-testing/tiny-random-bert")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-BD49ADCF - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_tokenization_utils.py:62`
- **数据流:** from_pretrained() downloads model from Hugging Face Hub without specifying a revision/tag/commit hash
- **判断理由:** Bandit B615: Same vulnerability as line 58. The mock test still performs an initial download without revision pinning.

**代码片段:**
```
_ = BertTokenizer.from_pretrained("hf-internal-testing/tiny-random-bert")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-9DF36508 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_tokenization_utils.py:76`
- **数据流:** from_pretrained() downloads model from Hugging Face Hub without specifying a revision/tag/commit hash
- **判断理由:** Bandit B615: Same vulnerability pattern - downloading GPT2 tokenizer without revision pinning.

**代码片段:**
```
_ = GPT2TokenizerFast.from_pretrained("openai-community/gpt2")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B7DFCD8E - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_tokenization_utils.py:80`
- **数据流:** from_pretrained() downloads model from Hugging Face Hub without specifying a revision/tag/commit hash
- **判断理由:** Bandit B615: Same vulnerability pattern as line 76.

**代码片段:**
```
_ = GPT2TokenizerFast.from_pretrained("openai-community/gpt2")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-80EC1333 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_tokenization_utils.py:91`
- **数据流:** from_pretrained() loads a tokenizer from a local file path, but the file was downloaded from Hugging Face Hub without revision pinning
- **判断理由:** Bandit B615: While the tokenizer is loaded from a local file, the file was originally downloaded from Hugging Face Hub (via http_get) without revision pinning, making the downloaded content potentially untrusted.

**代码片段:**
```
_ = AlbertTokenizer.from_pretrained(tmp_file)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-0B9ACF0C - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_tokenization_utils.py:103`
- **数据流:** from_pretrained() downloads model from Hugging Face Hub without specifying a revision/tag/commit hash
- **判断理由:** Bandit B615: Same vulnerability pattern - using AutoTokenizer without revision pinning.

**代码片段:**
```
tokenizer = AutoTokenizer.from_pretrained("hf-internal-testing/tiny-random-gpt2")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-3ECB3B5C - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_tokenization_utils.py:139`
- **数据流:** from_pretrained() downloads model from Hugging Face Hub without specifying a revision/tag/commit hash
- **判断理由:** Bandit B615: Loading tokenizer from a pushed repository without revision pinning.

**代码片段:**
```
new_tokenizer = BertTokenizer.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-5B634804 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_tokenization_utils.py:157`
- **数据流:** from_pretrained() downloads model from Hugging Face Hub without specifying a revision/tag/commit hash
- **判断理由:** Bandit B615: Same vulnerability pattern as line 139.

**代码片段:**
```
new_tokenizer = BertTokenizer.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-33FB35C4 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_tokenization_utils.py:173`
- **数据流:** from_pretrained() downloads model from Hugging Face Hub without specifying a revision/tag/commit hash
- **判断理由:** Bandit B615: Same vulnerability pattern - loading from organization repository without revision pinning.

**代码片段:**
```
new_tokenizer = BertTokenizer.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-F3450FEC - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_tokenization_utils.py:191`
- **数据流:** from_pretrained() downloads model from Hugging Face Hub without specifying a revision/tag/commit hash
- **判断理由:** Bandit B615: Same vulnerability pattern as line 173.

**代码片段:**
```
new_tokenizer = BertTokenizer.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-62D1A069 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_tokenization_utils.py:212`
- **数据流:** from_pretrained() downloads model from Hugging Face Hub without specifying a revision/tag/commit hash
- **判断理由:** Bandit B615: Same vulnerability pattern - loading from pushed repository without revision pinning.

**代码片段:**
```
new_tokenizer = BertTokenizer.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-23CA30AF - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_tokenization_utils.py:233`
- **数据流:** from_pretrained() downloads model from Hugging Face Hub without specifying a revision/tag/commit hash
- **判断理由:** Bandit B615: Same vulnerability pattern - loading from organization repository without revision pinning.

**代码片段:**
```
new_tokenizer = BertTokenizer.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-CB37542B - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_tokenization_utils.py:239`
- **数据流:** from_pretrained() downloads model from Hugging Face Hub without specifying a revision/tag/commit hash
- **判断理由:** Bandit B615: Same vulnerability pattern as line 233.

**代码片段:**
```
new_tokenizer = BertTokenizer.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-CD80BD82 - Unsafe Hugging Face Hub download without revision pinning

- **严重等级:** HIGH
- **文件位置:** `tests/utils/test_tokenization_utils.py:242`
- **数据流:** from_pretrained() downloads model from Hugging Face Hub without specifying a revision/tag/commit hash
- **判断理由:** Bandit B615: Same vulnerability pattern - loading from organization repository without revision pinning.

**代码片段:**
```
new_tokenizer = BertTokenizer.from_pretrained(tmp_repo)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-5C391152 - 不安全的YAML加载

- **严重等级:** HIGH
- **文件位置:** `utils/check_doc_toc.py:83`
- **数据流:** 文件路径PATH_TO_TOC是硬编码的常量'docs/source/en/_toctree.yml'，但yaml.safe_load()加载用户可控的YAML文件内容。虽然这里使用了safe_load，但文件内容可能被恶意修改（如通过其他漏洞或未授权访问），导致加载恶意YAML数据。
- **判断理由:** 虽然使用了yaml.safe_load()而不是yaml.load()，避免了任意代码执行的风险，但YAML文件本身可能被外部篡改。如果攻击者能够修改_toctree.yml文件内容，可以注入恶意YAML结构（如递归引用导致拒绝服务），或利用YAML解析器的其他已知漏洞。此外，文件路径是硬编码的，但文件内容来源不可信，存在潜在风险。

**代码片段:**
```
with open(PATH_TO_TOC, encoding="utf-8") as f:
    content = yaml.safe_load(f.read())
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-98F08113 - 路径遍历

- **严重等级:** MEDIUM
- **文件位置:** `utils/check_doc_toc.py:83`
- **数据流:** PATH_TO_TOC是硬编码的常量字符串，没有用户输入参与路径构造。但文件路径是相对路径，依赖于当前工作目录。如果脚本从恶意目录执行，可能读取到非预期的文件。
- **判断理由:** 虽然路径是硬编码的，但使用相对路径存在潜在风险。如果攻击者能够控制脚本的执行目录（例如通过符号链接攻击或恶意的工作目录设置），可能导致读取到恶意文件。不过，由于路径是固定的且没有用户输入拼接，实际利用难度较高。

**代码片段:**
```
PATH_TO_TOC = "docs/source/en/_toctree.yml"
...
with open(PATH_TO_TOC, encoding="utf-8") as f:
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-84BEE987 - 不安全的文件写入

- **严重等级:** MEDIUM
- **文件位置:** `utils/check_doc_toc.py:103`
- **数据流:** 当overwrite=True时，脚本会打开同一个YAML文件进行写入。写入的内容来自yaml.dump()序列化的数据，这些数据来源于之前读取并处理过的YAML内容。
- **判断理由:** 文件写入操作使用了硬编码的路径，没有进行路径验证或权限检查。如果文件被符号链接替换，可能导致写入到非预期的位置。此外，写入操作没有使用临时文件+原子替换的模式，在写入过程中如果程序崩溃，可能导致文件损坏。

**代码片段:**
```
with open(PATH_TO_TOC, "w", encoding="utf-8") as f:
    f.write(yaml.dump(content, allow_unicode=True))
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-9EA14A0E - 拒绝服务风险

- **严重等级:** LOW
- **文件位置:** `utils/check_doc_toc.py:83`
- **数据流:** YAML文件内容被完整加载到内存中。如果文件被恶意构造为包含大量嵌套结构或超大文件，可能导致内存耗尽。
- **判断理由:** 虽然yaml.safe_load()比yaml.load()更安全，但仍然可能被用于拒绝服务攻击。攻击者如果能够修改_toctree.yml文件，可以构造一个包含深度嵌套或大量重复键的YAML文件，导致解析时消耗大量CPU和内存资源。

**代码片段:**
```
content = yaml.safe_load(f.read())
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-F01ECA93 - 命令注入

- **严重等级:** CRITICAL
- **文件位置:** `utils/check_self_hosted_runner.py:13`
- **数据流:** 用户通过命令行参数 --token 输入 token 值 -> 直接通过 f-string 拼接进 cmd 字符串 -> 传递给 subprocess.run 的 shell=True 执行
- **判断理由:** token 参数来自用户输入（命令行参数），未经任何过滤或转义直接通过 f-string 拼接到 curl 命令中，并使用 shell=True 执行。攻击者可以构造恶意 token 值（如包含分号、管道符等）注入任意命令，导致远程代码执行。

**代码片段:**
```
cmd = (
    f'curl -H "Accept: application/vnd.github+json" -H "Authorization: Bearer {token}"'
    " https://api.github.com/repos/huggingface/transformers/actions/runners"
)
output = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-F15D1C6F - 硬编码凭证

- **严重等级:** MEDIUM
- **文件位置:** `utils/check_self_hosted_runner.py:13`
- **数据流:** token 作为命令行参数传入，在 curl 命令的 Authorization 头中明文传递
- **判断理由:** GitHub token 通过命令行参数传递，会在进程列表（如 ps aux）中暴露，且 curl 命令执行时 token 以明文形式出现在系统日志或历史记录中，存在凭证泄露风险。

**代码片段:**
```
cmd = (
    f'curl -H "Accept: application/vnd.github+json" -H "Authorization: Bearer {token}"'
    " https://api.github.com/repos/huggingface/transformers/actions/runners"
)
output = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-4E7CB4B4 - 路径遍历

- **严重等级:** HIGH
- **文件位置:** `utils/check_tf_ops.py:48`
- **数据流:** 用户通过命令行参数 --saved_model_path 传入路径 -> 直接传递给 open() 函数打开文件
- **判断理由:** saved_model_path 参数直接来自用户输入（命令行参数），未经任何路径校验或规范化处理就被传递给 open() 函数。攻击者可以通过传入包含路径遍历序列（如 ../）的路径来读取系统上的任意文件，导致敏感信息泄露。

**代码片段:**
```
with open(saved_model_path, "rb") as f:
    saved_model.ParseFromString(f.read())
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-E7A7DCA1 - 路径遍历

- **严重等级:** MEDIUM
- **文件位置:** `utils/check_tf_ops.py:44`
- **数据流:** REPO_PATH 硬编码为 '.' -> 与固定路径拼接 -> 打开文件
- **判断理由:** 虽然 REPO_PATH 当前硬编码为 '.'，但如果未来修改为可配置或用户可控的值，结合 os.path.join 可能导致路径遍历。当前版本风险较低，但存在潜在的安全隐患。

**代码片段:**
```
with open(os.path.join(REPO_PATH, "utils", "tf_ops", "onnx.json")) as f:
    onnx_opsets = json.load(f)["opsets"]
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-81AF9C64 - 不安全的异常处理

- **严重等级:** LOW
- **文件位置:** `utils/check_tf_ops.py:73`
- **数据流:** 用户通过 --opset 参数控制 opset 值 -> 拼接进异常消息
- **判断理由:** 异常消息中直接拼接了用户可控的 opset 参数，虽然不会导致代码执行，但可能造成信息泄露或日志注入。更安全的做法是使用参数化字符串或日志记录。

**代码片段:**
```
raise Exception(f"Found the following incompatible ops for the opset {opset}:\n" + incompatible_ops)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-E48E319C - 不安全的Hugging Face Hub下载（未固定版本）

- **严重等级:** HIGH
- **文件位置:** `utils/create_dummy_models.py:283`
- **数据流:** 静态工具检测到第283行存在from_pretrained()调用，未指定revision参数来固定模型版本
- **判断理由:** 使用from_pretrained()从Hugging Face Hub下载模型时，如果没有指定revision参数，将默认下载最新版本。这可能导致供应链攻击，因为攻击者可以上传恶意版本到Hub，而代码会自动下载恶意版本。建议始终指定具体的revision（如commit hash或tag）来固定模型版本。

**代码片段:**
```
from_pretrained()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-BE738CA6 - 不安全的Hugging Face Hub下载（未固定版本）

- **严重等级:** HIGH
- **文件位置:** `utils/create_dummy_models.py:633`
- **数据流:** 静态工具检测到第633行存在from_pretrained()调用，未指定revision参数来固定模型版本
- **判断理由:** 与第283行相同的问题，使用from_pretrained()从Hugging Face Hub下载模型时未固定版本，存在供应链攻击风险。攻击者可能上传恶意模型版本，导致代码自动下载并执行恶意代码。

**代码片段:**
```
from_pretrained()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-4E7C44C2 - 不安全的Hugging Face Hub下载（未固定版本）

- **严重等级:** HIGH
- **文件位置:** `utils/create_dummy_models.py:1083`
- **数据流:** 静态工具检测到第1083行存在load_dataset()调用，未指定revision参数来固定数据集版本
- **判断理由:** 使用load_dataset()从Hugging Face Hub下载数据集时未指定revision参数，存在供应链攻击风险。攻击者可能上传恶意数据集版本，导致代码自动下载并处理恶意数据。建议始终指定具体的revision参数来固定数据集版本。

**代码片段:**
```
load_dataset()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-6AFF7E25 - SSRF (Server-Side Request Forgery)

- **严重等级:** MEDIUM
- **文件位置:** `utils/deprecate_models.py:32`
- **数据流:** 第31行定义硬编码URL 'https://pypi.org/pypi/transformers/json' → 第32行直接使用requests.get()发起HTTP请求，未设置timeout参数
- **判断理由:** requests.get()调用没有设置timeout参数，可能导致请求被挂起或阻塞。虽然URL是硬编码的，不存在用户输入注入风险，但缺少超时设置可能导致资源耗尽或服务不可用。根据bandit规则B113，所有网络请求都应设置合理的超时时间。

**代码片段:**
```
release_data = requests.get(url).json()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-1E7F2B73 - 路径遍历

- **严重等级:** HIGH
- **文件位置:** `utils/diff_model_converter.py:48`
- **数据流:** 用户通过module_name参数传入模块名 -> importlib.util.find_spec(module_name)解析模块路径 -> spec.origin获取文件路径 -> open(spec.origin, 'r')打开并读取文件内容
- **判断理由:** 函数get_module_source_from_name接受外部传入的module_name参数，通过importlib.util.find_spec解析模块路径并直接使用open()读取文件。虽然importlib.util.find_spec会限制在Python模块搜索路径内，但如果攻击者能够控制module_name参数，仍可能通过构造特殊的模块名（如包含路径遍历字符）访问到预期外的文件。该函数没有对module_name进行任何校验或白名单限制，存在路径遍历风险。

**代码片段:**
```
def get_module_source_from_name(module_name: str) -> str:
    spec = importlib.util.find_spec(module_name)
    if spec is None or spec.origin is None:
        return f"Module {module_name} not found"
    with open(spec.origin, "r") as file:
        source_code = file.read()
    return source_code
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-EE39219E - 信息泄露

- **严重等级:** MEDIUM
- **文件位置:** `utils/diff_model_converter.py:48`
- **数据流:** 用户传入module_name -> 模块查找失败时 -> 错误信息中包含用户输入的module_name -> 返回给调用方
- **判断理由:** 当模块查找失败时，函数直接将用户输入的module_name拼接到错误信息中返回。这可能导致信息泄露，攻击者可以通过观察错误信息来探测系统上是否存在特定模块或文件路径。虽然风险较低，但属于安全最佳实践问题。

**代码片段:**
```
def get_module_source_from_name(module_name: str) -> str:
    spec = importlib.util.find_spec(module_name)
    if spec is None or spec.origin is None:
        return f"Module {module_name} not found"
    with open(spec.origin, "r") as file:
        source_code = file.read()
    return source_code
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-A06CF615 - SSRF (Server-Side Request Forgery)

- **严重等级:** HIGH
- **文件位置:** `utils/download_glue_data.py:50`
- **数据流:** 用户通过--tasks参数控制task变量 -> task作为TASK2PATH字典的键 -> 获取URL -> urllib.request.urlretrieve发起请求
- **判断理由:** 虽然TASK2PATH是硬编码的字典，但用户可以通过--tasks参数控制下载哪个URL。如果攻击者能够控制TASK2PATH字典的内容（例如通过配置文件注入或依赖劫持），或者利用未预期的URL协议（如file://），可能导致SSRF攻击。bandit工具标记了B310问题，表明需要审计urlopen允许的协议scheme。

**代码片段:**
```
urllib.request.urlretrieve(TASK2PATH[task], data_file)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-1253E22E - SSRF (Server-Side Request Forgery)

- **严重等级:** HIGH
- **文件位置:** `utils/download_glue_data.py:69`
- **数据流:** 硬编码URL MRPC_TRAIN -> urllib.request.urlretrieve发起请求
- **判断理由:** 虽然MRPC_TRAIN是硬编码的URL，但bandit工具仍然标记了B310问题。如果攻击者能够修改MRPC_TRAIN变量的值（例如通过环境变量注入或代码修改），可能导致SSRF攻击。此外，如果URL指向内部服务，可能造成信息泄露。

**代码片段:**
```
urllib.request.urlretrieve(MRPC_TRAIN, mrpc_train_file)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-5E95E5BA - SSRF (Server-Side Request Forgery)

- **严重等级:** HIGH
- **文件位置:** `utils/download_glue_data.py:70`
- **数据流:** 硬编码URL MRPC_TEST -> urllib.request.urlretrieve发起请求
- **判断理由:** 与第69行类似，虽然MRPC_TEST是硬编码的URL，但bandit工具标记了B310问题。如果攻击者能够修改MRPC_TEST变量的值，可能导致SSRF攻击。

**代码片段:**
```
urllib.request.urlretrieve(MRPC_TEST, mrpc_test_file)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-98EA73DE - SSRF (Server-Side Request Forgery)

- **严重等级:** HIGH
- **文件位置:** `utils/download_glue_data.py:75`
- **数据流:** 硬编码字典键"MRPC" -> 从TASK2PATH获取URL -> urllib.request.urlretrieve发起请求
- **判断理由:** 虽然TASK2PATH["MRPC"]是硬编码的URL，但bandit工具标记了B310问题。如果攻击者能够修改TASK2PATH字典的内容，可能导致SSRF攻击。

**代码片段:**
```
urllib.request.urlretrieve(TASK2PATH["MRPC"], os.path.join(mrpc_dir, "dev_ids.tsv"))
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-05DFE802 - SSRF (Server-Side Request Forgery)

- **严重等级:** HIGH
- **文件位置:** `utils/download_glue_data.py:111`
- **数据流:** 硬编码字典键"diagnostic" -> 从TASK2PATH获取URL -> urllib.request.urlretrieve发起请求
- **判断理由:** 虽然TASK2PATH["diagnostic"]是硬编码的URL，但bandit工具标记了B310问题。如果攻击者能够修改TASK2PATH字典的内容，可能导致SSRF攻击。

**代码片段:**
```
urllib.request.urlretrieve(TASK2PATH["diagnostic"], data_file)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-DC893482 - 不安全的文件操作 - 路径遍历

- **严重等级:** MEDIUM
- **文件位置:** `utils/download_glue_data.py:48`
- **数据流:** 用户通过--tasks参数控制task变量 -> task用于构造文件名 -> 下载文件 -> 解压到data_dir目录
- **判断理由:** 虽然task变量经过get_tasks函数验证，但文件名直接使用用户输入构造。如果攻击者能够绕过验证（例如通过注入特殊字符），可能导致路径遍历攻击。此外，zipfile.extractall()存在zip slip漏洞风险，如果zip文件中包含路径遍历的条目（如../恶意文件），可能导致文件被解压到预期目录之外。

**代码片段:**
```
data_file = f"{task}.zip"
urllib.request.urlretrieve(TASK2PATH[task], data_file)
with zipfile.ZipFile(data_file) as zip_ref:
    zip_ref.extractall(data_dir)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-5607A2AD - 不安全的文件操作 - 路径遍历

- **严重等级:** MEDIUM
- **文件位置:** `utils/download_glue_data.py:64`
- **数据流:** 用户通过--path_to_mrpc参数控制path_to_data变量 -> 用于构造文件路径 -> 后续打开文件
- **判断理由:** path_to_data变量直接来自用户输入（--path_to_mrpc参数），虽然预期是目录路径，但未进行充分的路径验证。攻击者可以通过提供包含路径遍历序列（如../）的路径，访问或操作系统上的任意文件。

**代码片段:**
```
mrpc_train_file = os.path.join(path_to_data, "msr_paraphrase_train.txt")
mrpc_test_file = os.path.join(path_to_data, "msr_paraphrase_test.txt")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-751ABBF4 - 不安全的文件操作 - 路径遍历

- **严重等级:** MEDIUM
- **文件位置:** `utils/download_glue_data.py:78`
- **数据流:** 用户通过--path_to_mrpc参数间接影响mrpc_dir路径 -> 打开文件
- **判断理由:** mrpc_dir由data_dir和"MRPC"拼接而成，而data_dir来自用户输入（--data_dir参数）。如果攻击者提供包含路径遍历序列的data_dir，可能导致访问系统上的任意文件。

**代码片段:**
```
with open(os.path.join(mrpc_dir, "dev_ids.tsv"), encoding="utf8") as ids_fh:
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-658BC870 - 不安全的文件操作 - 路径遍历

- **严重等级:** MEDIUM
- **文件位置:** `utils/download_glue_data.py:108`
- **数据流:** 用户通过--data_dir参数控制data_dir变量 -> 用于构造文件路径 -> 下载文件到该路径
- **判断理由:** data_dir来自用户输入（--data_dir参数），未进行充分的路径验证。攻击者可以通过提供包含路径遍历序列的data_dir，将文件下载到系统上的任意位置。

**代码片段:**
```
data_file = os.path.join(data_dir, "diagnostic", "diagnostic.tsv")
urllib.request.urlretrieve(TASK2PATH["diagnostic"], data_file)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-5D41B687 - SSRF (Server-Side Request Forgery) - Missing Timeout

- **严重等级:** MEDIUM
- **文件位置:** `utils/get_ci_error_statistics.py:21`
- **数据流:** 用户输入workflow_run_id通过f-string拼接构造URL -> requests.get()调用未设置timeout参数
- **判断理由:** requests.get()调用未设置timeout参数，可能导致请求被长时间阻塞，造成资源耗尽或SSRF攻击。攻击者可以通过控制workflow_run_id参数使请求指向恶意或内部服务，且无超时限制会加剧风险。

**代码片段:**
```
result = requests.get(url, headers=headers).json()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B91CE739 - SSRF (Server-Side Request Forgery) - Missing Timeout

- **严重等级:** MEDIUM
- **文件位置:** `utils/get_ci_error_statistics.py:29`
- **数据流:** 用户输入workflow_run_id通过f-string拼接构造URL -> requests.get()调用未设置timeout参数
- **判断理由:** 分页请求中同样未设置timeout参数，攻击者可通过控制workflow_run_id参数构造恶意URL，导致请求被长时间阻塞。

**代码片段:**
```
result = requests.get(url + f"&page={i + 2}", headers=headers).json()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-0E59FA33 - SSRF (Server-Side Request Forgery) - Missing Timeout

- **严重等级:** MEDIUM
- **文件位置:** `utils/get_ci_error_statistics.py:47`
- **数据流:** 用户输入workflow_run_id通过f-string拼接构造URL -> requests.get()调用未设置timeout参数
- **判断理由:** get_job_links函数中同样未设置timeout参数，存在相同的SSRF和资源耗尽风险。

**代码片段:**
```
result = requests.get(url, headers=headers).json()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-108C0B9E - SSRF (Server-Side Request Forgery) - Missing Timeout

- **严重等级:** MEDIUM
- **文件位置:** `utils/get_ci_error_statistics.py:55`
- **数据流:** 用户输入workflow_run_id通过f-string拼接构造URL -> requests.get()调用未设置timeout参数
- **判断理由:** get_job_links函数的分页请求同样未设置timeout参数。

**代码片段:**
```
result = requests.get(url + f"&page={i + 2}", headers=headers).json()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-4783C209 - SSRF (Server-Side Request Forgery) - Missing Timeout

- **严重等级:** MEDIUM
- **文件位置:** `utils/get_ci_error_statistics.py:73`
- **数据流:** 用户输入worflow_run_id通过f-string拼接构造URL -> requests.get()调用未设置timeout参数
- **判断理由:** get_artifacts_links函数中未设置timeout参数，存在SSRF风险。

**代码片段:**
```
result = requests.get(url, headers=headers).json()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-7A40FB49 - SSRF (Server-Side Request Forgery) - Missing Timeout

- **严重等级:** MEDIUM
- **文件位置:** `utils/get_ci_error_statistics.py:81`
- **数据流:** 用户输入worflow_run_id通过f-string拼接构造URL -> requests.get()调用未设置timeout参数
- **判断理由:** get_artifacts_links函数的分页请求同样未设置timeout参数。

**代码片段:**
```
result = requests.get(url + f"&page={i + 2}", headers=headers).json()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-A082F3D5 - SSRF (Server-Side Request Forgery) - Missing Timeout

- **严重等级:** MEDIUM
- **文件位置:** `utils/get_ci_error_statistics.py:102`
- **数据流:** 用户输入artifact_url通过函数参数传入 -> requests.get()调用未设置timeout参数
- **判断理由:** download_artifact函数中第一个requests.get()调用未设置timeout参数，攻击者可通过控制artifact_url参数发起SSRF攻击。

**代码片段:**
```
result = requests.get(artifact_url, headers=headers, allow_redirects=False)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-0105E6D1 - SSRF (Server-Side Request Forgery) - Missing Timeout

- **严重等级:** MEDIUM
- **文件位置:** `utils/get_ci_error_statistics.py:104`
- **数据流:** 从响应头中获取的Location URL -> requests.get()调用未设置timeout参数
- **判断理由:** download_artifact函数中第二个requests.get()调用未设置timeout参数，且allow_redirects=True可能被利用进行重定向攻击。

**代码片段:**
```
response = requests.get(download_url, allow_redirects=True)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-54F03523 - SSRF (Server-Side Request Forgery)

- **严重等级:** MEDIUM
- **文件位置:** `utils\get_github_job_time.py:37`
- **数据流:** 用户输入 args.workflow_run_id -> get_job_time(workflow_run_id) -> url 拼接 -> requests.get(url)
- **判断理由:** workflow_run_id 直接来自用户输入，并拼接到 URL 中。虽然 URL 的 base 部分固定为 GitHub API，但攻击者可以通过注入特殊字符（如路径遍历或参数污染）来操纵请求的目标，例如传入 '../' 或 '?' 等字符，可能导致访问非预期的 API 端点或资源。

**代码片段:**
```
result = requests.get(url, headers=headers).json()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-07BAE395 - SSRF (Server-Side Request Forgery)

- **严重等级:** MEDIUM
- **文件位置:** `utils\get_github_job_time.py:45`
- **数据流:** 用户输入 args.workflow_run_id -> get_job_time(workflow_run_id) -> url 拼接 -> requests.get(url + &page=...)
- **判断理由:** 与第37行类似，workflow_run_id 直接拼接到 URL 中，攻击者可通过注入特殊字符操纵请求目标。虽然 page 参数是内部生成的整数，但 URL 的 base 部分仍受用户输入影响。

**代码片段:**
```
result = requests.get(url + f"&page={i + 2}", headers=headers).json()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-851A52E9 - Missing Request Timeout

- **严重等级:** MEDIUM
- **文件位置:** `utils\get_github_job_time.py:37`
- **数据流:** requests.get 调用未设置 timeout 参数
- **判断理由:** requests.get 未设置 timeout 参数，可能导致请求被长时间阻塞，造成资源耗尽或拒绝服务（DoS）攻击。攻击者可以构造慢响应或无限挂起的请求来消耗系统资源。

**代码片段:**
```
result = requests.get(url, headers=headers).json()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-8B520A2A - Missing Request Timeout

- **严重等级:** MEDIUM
- **文件位置:** `utils\get_github_job_time.py:45`
- **数据流:** requests.get 调用未设置 timeout 参数
- **判断理由:** 与第37行相同，第二个 requests.get 调用也未设置 timeout 参数，存在同样的资源耗尽风险。

**代码片段:**
```
result = requests.get(url + f"&page={i + 2}", headers=headers).json()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-94A68990 - Information Exposure via Exception Handling

- **严重等级:** LOW
- **文件位置:** `utils\get_github_job_time.py:49`
- **数据流:** 异常发生时，traceback.format_exc() 输出完整的堆栈信息到控制台
- **判断理由:** 在异常处理中直接打印完整的 traceback 信息，可能泄露内部路径、代码结构或敏感数据（如 token 信息）。虽然当前 token 未在异常中直接暴露，但堆栈信息可能包含其他敏感上下文。

**代码片段:**
```
print(f"Unknown error, could not fetch links:\n{traceback.format_exc()}")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-448EC4CB - 命令注入

- **严重等级:** CRITICAL
- **文件位置:** `utils\get_modified_files.py:30`
- **数据流:** 用户通过命令行参数sys.argv[1:]传入，但此处的命令是硬编码的字符串，不直接受用户输入影响。然而，后续的git diff命令拼接了fork_point_sha，而fork_point_sha来自git命令输出，若git仓库被恶意控制（如通过恶意分支名），可能导致命令注入。
- **判断理由:** 虽然fork_point_sha来自git命令输出，看似安全，但若攻击者能控制git仓库（如通过恶意分支名或标签），fork_point_sha可能包含特殊字符（如分号、管道符），导致命令注入。subprocess.check_output使用shell=False（默认），但split()可能无法正确分割包含空格的恶意输出，且命令字符串直接拼接，存在风险。

**代码片段:**
```
fork_point_sha = subprocess.check_output("git merge-base main HEAD".split()).decode("utf-8")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-5A598A16 - 命令注入

- **严重等级:** CRITICAL
- **文件位置:** `utils\get_modified_files.py:31`
- **数据流:** fork_point_sha来自第30行的git命令输出，该输出可能被攻击者控制（如通过恶意分支名）。fork_point_sha被直接拼接到f-string中，然后通过split()分割成列表传递给subprocess.check_output。
- **判断理由:** 如果fork_point_sha包含空格或特殊字符（如; rm -rf /），split()会将其分割成多个参数，导致命令注入。例如，若fork_point_sha为'abc; echo pwned'，则split()后得到['git', 'diff', '--diff-filter=d', '--name-only', 'abc;', 'echo', 'pwned']，subprocess会执行额外的命令。这是典型的命令注入漏洞，攻击者可利用恶意分支名执行任意命令。

**代码片段:**
```
modified_files = (
    subprocess.check_output(f"git diff --diff-filter=d --name-only {fork_point_sha}".split()).decode("utf-8").split()
)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-8DD7B224 - SSRF (Server-Side Request Forgery)

- **严重等级:** MEDIUM
- **文件位置:** `utils/get_previous_daily_ci.py:27`
- **数据流:** 用户输入token通过headers参数传入requests.get()，但URL是硬编码的GitHub API地址，攻击者无法直接控制URL。然而，如果token被泄露或中间人攻击，可能导致请求被重定向到恶意服务器。
- **判断理由:** requests.get()调用未设置timeout参数，可能导致请求阻塞或无限等待。同时，如果攻击者能够控制网络环境（如中间人攻击），可能将请求重定向到内部服务，造成SSRF风险。但URL是硬编码的，风险相对较低。

**代码片段:**
```
result = requests.get(url, headers=headers).json()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-AF5C4443 - 不安全的HTTP请求（缺少超时）

- **严重等级:** MEDIUM
- **文件位置:** `utils/get_previous_daily_ci.py:27`
- **数据流:** 直接调用requests.get()未设置timeout参数，可能导致程序挂起或资源耗尽。
- **判断理由:** bandit工具已标记此问题（B113）。未设置超时的HTTP请求可能被恶意服务器或网络故障导致无限期阻塞，造成拒绝服务（DoS）风险。

**代码片段:**
```
result = requests.get(url, headers=headers).json()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-BA9561A4 - 路径遍历

- **严重等级:** LOW
- **文件位置:** `utils/get_previous_daily_ci.py:62`
- **数据流:** artifact_name来自函数参数，可能包含恶意路径字符（如../），导致路径遍历。
- **判断理由:** 虽然artifact_name预期来自GitHub artifacts列表，但函数参数未进行任何校验。如果攻击者能够控制artifact_name参数（例如通过其他漏洞或配置错误），可能通过路径遍历写入任意文件。但实际调用中artifact_names是硬编码列表，风险较低。

**代码片段:**
```
artifact_zip_path = os.path.join(output_dir, f"{artifact_name}.zip")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-3BC262D2 - 不安全的文件解压（Zip Slip）

- **严重等级:** HIGH
- **文件位置:** `utils/get_previous_daily_ci.py:65`
- **数据流:** 从ZIP文件中读取文件名，但未对文件名进行路径校验。如果ZIP文件中包含恶意构造的路径（如../../etc/passwd），可能导致路径遍历。
- **判断理由:** 代码仅检查了os.path.isdir(filename)，但未阻止包含路径分隔符的文件名。如果ZIP文件被篡改，包含带有../的条目，虽然当前代码仅读取内容到内存，但后续使用results字典时可能造成信息泄露或进一步攻击。

**代码片段:**
```
with zipfile.ZipFile(artifact_zip_path) as z:
    for filename in z.namelist():
        if not os.path.isdir(filename):
            with z.open(filename) as f:
                results[artifact_name][filename] = f.read().decode("UTF-8")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-641363FC - 不安全的文件操作 - 路径遍历

- **严重等级:** MEDIUM
- **文件位置:** `utils/models_to_deprecate.py:72`
- **数据流:** models_dir 来自 PATH_TO_REPO / "src/transformers/models"，PATH_TO_REPO 是硬编码的路径，没有用户输入。但 glob 模式匹配可能受到符号链接影响。
- **判断理由:** 虽然 models_dir 不是用户直接控制的，但 glob 模式匹配可能跟随符号链接，如果攻击者能够在文件系统中创建符号链接，可能导致访问预期外的文件。不过由于路径是硬编码的，实际风险较低。

**代码片段:**
```
models = glob.glob(os.path.join(models_dir, "*/modeling_*.py"))
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-15EF5026 - 不安全的文件操作 - 缓存文件路径固定

- **严重等级:** LOW
- **文件位置:** `utils/models_to_deprecate.py:80`
- **数据流:** 缓存文件路径 'models_info.json' 是硬编码的相对路径，从当前工作目录读取。如果脚本在共享目录中运行，可能被其他用户篡改。
- **判断理由:** 使用硬编码的相对路径读取缓存文件，如果攻击者能够在当前工作目录创建恶意的 models_info.json 文件，可能导致读取恶意数据。但 JSON 解析本身不会导致代码执行，风险较低。

**代码片段:**
```
if use_cache and os.path.exists("models_info.json"):
    with open("models_info.json", "r") as f:
        models_info = json.load(f)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-73C8CF60 - 不安全的文件操作 - 写入固定路径文件

- **严重等级:** LOW
- **文件位置:** `utils/models_to_deprecate.py:103`
- **数据流:** 将模型信息写入硬编码的相对路径 'models_info.json'，数据来自 HuggingFace Hub API 的响应。
- **判断理由:** 写入固定路径文件可能导致信息泄露或文件覆盖，但数据来自可信的 API 且路径是相对路径，风险较低。

**代码片段:**
```
with open("models_info.json", "w") as f:
    json.dump(models_info, f, indent=4)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-32FAE9D5 - 不安全的日志输出 - 敏感信息泄露

- **严重等级:** LOW
- **文件位置:** `utils/models_to_deprecate.py:113`
- **数据流:** 打印模型名称、下载量和日期信息到标准输出，这些信息来自 HuggingFace Hub 公开数据。
- **判断理由:** 虽然打印的信息是公开数据，但在某些环境中日志可能被收集和存储，存在轻微的信息泄露风险。但考虑到数据本身就是公开的，风险很低。

**代码片段:**
```
print(f"\nModel: {model}")
print(f"Downloads: {n_downloads}")
print(f"Date: {info['first_commit_datetime']}")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-A06236E6 - Missing Request Timeout

- **严重等级:** MEDIUM
- **文件位置:** `utils/notification_service.py:945`
- **数据流:** requests库调用未设置timeout参数，可能导致请求永久挂起
- **判断理由:** Bandit静态分析工具检测到第945行存在requests调用未设置timeout。这可能导致程序在请求外部服务时无限期阻塞，造成资源耗尽或拒绝服务(DoS)风险。

**代码片段:**
```
requests without timeout
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-38895A60 - Missing Request Timeout

- **严重等级:** MEDIUM
- **文件位置:** `utils/notification_service.py:954`
- **数据流:** requests库调用未设置timeout参数，可能导致请求永久挂起
- **判断理由:** Bandit静态分析工具检测到第954行存在requests调用未设置timeout。与第945行相同的问题，可能导致程序在请求外部服务时无限期阻塞。

**代码片段:**
```
requests without timeout
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-963EC69D - Hardcoded Environment Variable Dependency

- **严重等级:** LOW
- **文件位置:** `utils/notification_service.py:30`
- **数据流:** 从环境变量读取Slack Bot Token用于初始化WebClient
- **判断理由:** 虽然使用了环境变量而非硬编码凭证，但代码中直接依赖环境变量CI_SLACK_BOT_TOKEN的存在。如果环境变量未设置，程序将抛出KeyError异常，可能导致信息泄露或服务中断。建议添加适当的错误处理。

**代码片段:**
```
client = WebClient(token=os.environ["CI_SLACK_BOT_TOKEN"])
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-1138BF85 - Hardcoded Environment Variable Dependency

- **严重等级:** LOW
- **文件位置:** `utils/notification_service.py:29`
- **数据流:** 初始化Hugging Face Hub API客户端
- **判断理由:** HfApi()默认会从环境变量读取Hugging Face API Token。如果未设置或设置不当，可能导致认证失败或使用错误的凭证。建议显式传递token参数并添加错误处理。

**代码片段:**
```
api = HfApi()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B6C8FB0C - Potential Information Disclosure via URL Construction

- **严重等级:** LOW
- **文件位置:** `utils/notification_service.py:130`
- **数据流:** 使用环境变量GITHUB_RUN_ID构建GitHub Actions URL
- **判断理由:** 代码中多次使用f-string拼接环境变量到URL中。虽然GITHUB_RUN_ID是公开信息，但这种模式如果扩展到其他敏感环境变量，可能导致信息泄露。建议对URL构建进行统一管理和验证。

**代码片段:**
```
url": f"https://github.com/huggingface/transformers/actions/runs/{os.environ['GITHUB_RUN_ID']}"
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-2A11E144 - 硬编码凭证

- **严重等级:** HIGH
- **文件位置:** `utils/notification_service_doc_tests.py:18`
- **数据流:** 环境变量CI_SLACK_BOT_TOKEN被直接用作Slack API的认证令牌
- **判断理由:** 虽然令牌来自环境变量而非硬编码，但代码中直接使用环境变量作为敏感凭证，如果环境变量泄露或日志中打印，可能导致凭证泄露。此外，代码中未对令牌进行任何保护或掩码处理。

**代码片段:**
```
client = WebClient(token=os.environ["CI_SLACK_BOT_TOKEN"])
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-D77F0DC9 - 信息泄露

- **严重等级:** MEDIUM
- **文件位置:** `utils/notification_service_doc_tests.py:147`
- **数据流:** payload包含测试结果和可能的敏感信息，通过print输出到控制台
- **判断理由:** 代码在发送消息前将payload打印到控制台，如果CI日志被公开访问，可能导致测试结果和内部信息泄露。

**代码片段:**
```
print("Sending the following payload")
print(json.dumps({"blocks": json.loads(payload)}))
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-282EEFD0 - 信息泄露

- **严重等级:** MEDIUM
- **文件位置:** `utils/notification_service_doc_tests.py:163`
- **数据流:** self.payload包含测试结果和可能的敏感信息，通过print输出到控制台
- **判断理由:** 同样在post方法中打印payload，可能导致敏感信息泄露到日志中。

**代码片段:**
```
print("Sending the following payload")
print(json.dumps({"blocks": json.loads(self.payload)}))
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-B2A64F18 - 不安全的反序列化

- **严重等级:** MEDIUM
- **文件位置:** `utils/notification_service_doc_tests.py:147`
- **数据流:** payload变量来自error_out方法的局部变量，但json.loads用于反序列化JSON字符串
- **判断理由:** 虽然payload是内部生成的JSON字符串，但使用json.loads反序列化用户可控数据可能导致安全问题。此处payload是硬编码的，风险较低，但模式不安全。

**代码片段:**
```
print(json.dumps({"blocks": json.loads(payload)}))
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-AE4EA936 - 不安全的反序列化

- **严重等级:** MEDIUM
- **文件位置:** `utils/notification_service_doc_tests.py:163`
- **数据流:** self.payload属性返回json.dumps(blocks)，然后又被json.loads解析
- **判断理由:** payload属性返回的是json.dumps的结果，然后又被json.loads解析，这种序列化再反序列化的操作虽然在此处无害，但可能掩盖数据流问题。

**代码片段:**
```
print(json.dumps({"blocks": json.loads(self.payload)}))
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-6C783741 - 未定义变量

- **严重等级:** HIGH
- **文件位置:** `utils/notification_service_doc_tests.py:155`
- **数据流:** 变量SLACK_REPORT_CHANNEL_ID在代码中未定义
- **判断理由:** SLACK_REPORT_CHANNEL_ID变量在代码中未定义或导入，会导致运行时NameError异常，使程序崩溃。这可能是遗漏的配置或导入错误。

**代码片段:**
```
channel=SLACK_REPORT_CHANNEL_ID,
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-4983C66B - 未定义变量

- **严重等级:** HIGH
- **文件位置:** `utils/notification_service_doc_tests.py:170`
- **数据流:** 变量SLACK_REPORT_CHANNEL_ID在代码中未定义
- **判断理由:** 同样在post方法中使用了未定义的SLACK_REPORT_CHANNEL_ID变量，会导致运行时错误。

**代码片段:**
```
channel=SLACK_REPORT_CHANNEL_ID,
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-58E2B86C - 硬编码凭证

- **严重等级:** HIGH
- **文件位置:** `utils/notification_service_quantization.py:33`
- **数据流:** 环境变量 CI_SLACK_BOT_TOKEN 被直接用作 Slack API 的认证令牌
- **判断理由:** 虽然使用了环境变量而非硬编码字符串，但 Slack Bot Token 是敏感凭证，直接通过环境变量传递并在代码中引用。如果环境变量泄露或日志中打印了该值，可能导致 Slack 频道被未授权访问。建议使用密钥管理服务或更安全的凭证管理方式。

**代码片段:**
```
client = WebClient(token=os.environ["CI_SLACK_BOT_TOKEN"])
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-E7368E10 - 硬编码凭证

- **严重等级:** HIGH
- **文件位置:** `utils/notification_service_quantization.py:107`
- **数据流:** 环境变量 SLACK_REPORT_CHANNEL 被用作 Slack 频道 ID
- **判断理由:** Slack 频道 ID 通过环境变量传递，虽然未硬编码，但敏感信息在代码中被引用。如果环境变量配置不当或泄露，可能导致消息发送到错误的频道。

**代码片段:**
```
channel=SLACK_REPORT_CHANNEL_ID
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-7451745F - 硬编码凭证

- **严重等级:** HIGH
- **文件位置:** `utils/notification_service_quantization.py:168`
- **数据流:** 环境变量 ACCESS_REPO_INFO_TOKEN 被用作 GitHub API 访问令牌
- **判断理由:** GitHub 访问令牌通过环境变量传递，这是敏感凭证。如果环境变量泄露，攻击者可能获得对 GitHub 仓库的未授权访问。建议使用 GitHub Actions 的 secrets 机制或更安全的凭证管理。

**代码片段:**
```
token=os.environ["ACCESS_REPO_INFO_TOKEN"]
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-BFDFC901 - 不安全的日志记录

- **严重等级:** MEDIUM
- **文件位置:** `utils/notification_service_quantization.py:97`
- **数据流:** payload 包含测试结果和可能的敏感信息，被打印到标准输出
- **判断理由:** 代码使用 print() 函数将包含测试结果和可能敏感信息的 payload 输出到标准输出。在 CI/CD 环境中，标准输出通常会被记录到日志中，可能导致敏感信息泄露。建议使用日志框架并配置适当的日志级别。

**代码片段:**
```
print("Sending the following payload")
print(json.dumps({"blocks": json.loads(payload)}))
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-6BA138A0 - 不安全的日志记录

- **严重等级:** MEDIUM
- **文件位置:** `utils/notification_service_quantization.py:120`
- **数据流:** 回复消息的 blocks 包含测试结果，被打印到标准输出
- **判断理由:** 同样使用 print() 输出可能包含敏感信息的回复消息内容到标准输出，存在信息泄露风险。

**代码片段:**
```
print("Sending the following reply")
print(json.dumps({"blocks": blocks}))
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-3AF694D7 - 不安全的反序列化

- **严重等级:** HIGH
- **文件位置:** `utils/notification_service_quantization.py:148`
- **数据流:** 命令行参数 arguments 通过 ast.literal_eval() 解析，arguments 来自 sys.argv[1:]
- **判断理由:** 虽然 ast.literal_eval() 比 eval() 安全，因为它只解析字面量表达式，但仍然存在风险。如果命令行参数来自不可信来源，攻击者可能构造恶意的字面量表达式导致拒绝服务或信息泄露。建议对输入进行严格的格式验证。

**代码片段:**
```
quantization_matrix = ast.literal_eval(arguments)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-FB017E5E - 不安全的系统调用

- **严重等级:** MEDIUM
- **文件位置:** `utils/notification_service_quantization.py:149`
- **数据流:** 从命令行参数解析得到的 quantization_matrix 列表元素被替换后用于后续的字符串拼接和文件路径操作
- **判断理由:** quantization_matrix 的元素来自命令行参数，经过 ast.literal_eval() 解析后，虽然进行了字符串替换，但未进行充分的输入验证。这些值后续被用于构建 artifact 名称和文件路径，可能存在路径遍历或注入风险。

**代码片段:**
```
quantization_matrix = [x.replace("quantization/", "quantization_") for x in quantization_matrix]
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-DCD33465 - 不安全的文件操作

- **严重等级:** MEDIUM
- **文件位置:** `utils/notification_service_quantization.py:155`
- **数据流:** quantization_matrix 中的元素被直接用于构建 artifact 名称字符串
- **判断理由:** quantization_matrix 的元素来自用户输入，被直接用于 f-string 格式化构建 artifact 名称。虽然这里只是字典键的检查，但如果后续这些值被用于文件路径操作，可能导致路径遍历漏洞。

**代码片段:**
```
quantization_results = {
    quant: {
        "failed": {"single": 0, "multi": 0},
        "success": 0,
        "time_spent": "",
        "failures": {},
        "job_link": {},
    }
    for quant in quantization_matrix
    if f"run_quantization_torch_gpu_{ quant }_test_reports" in available_artifacts
}
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-FCC60048 - 不安全的异常处理

- **严重等级:** LOW
- **文件位置:** `utils/notification_service_quantization.py:150`
- **数据流:** ast.literal_eval() 解析失败时捕获 SyntaxError 并重新抛出 ValueError
- **判断理由:** 异常处理中只捕获了 SyntaxError，但 ast.literal_eval() 可能抛出其他异常（如 ValueError）。不完整的异常捕获可能导致程序崩溃或信息泄露。建议捕获更广泛的异常类型。

**代码片段:**
```
except SyntaxError:
    Message.error_out(title, ci_title="")
    raise ValueError("Errored out.")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-AD4F2FF5 - 命令注入

- **严重等级:** CRITICAL
- **文件位置:** `utils/past_ci_versions.py:119`
- **数据流:** 用户通过命令行参数 --framework 和 --version 控制输入 -> args.framework 和 args.version -> 从 past_versions_testing 字典中获取 info -> info["install"] 被直接拼接到 os.system() 命令中执行
- **判断理由:** 虽然 info["install"] 来自硬编码的字典，但攻击者可以通过控制 --framework 和 --version 参数来访问字典中不同的键值对。如果字典中的 install 字符串包含恶意命令（如反引号、$() 等），将会被执行。更严重的是，如果未来字典被修改或扩展，可能引入恶意内容。使用 os.system() 且通过 shell 执行，存在命令注入风险。

**代码片段:**
```
os.system(f'echo "export INSTALL_CMD=\'{info["install"]}\'" >> ~/.profile')
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-232EB546 - 命令注入

- **严重等级:** CRITICAL
- **文件位置:** `utils/past_ci_versions.py:125`
- **数据流:** 用户通过命令行参数 --framework 控制输入 -> args.framework -> 从 past_versions_testing 字典中获取 info -> info["cuda"] 被赋值给 cuda 变量 -> cuda 被直接拼接到 os.system() 命令中执行
- **判断理由:** cuda 变量的值来自字典中硬编码的字符串，但同样存在通过 --framework 和 --version 参数控制访问路径的风险。如果 cuda 值包含 shell 特殊字符（如单引号、分号、反引号等），可能导致命令注入。使用 os.system() 通过 shell 执行命令，增加了注入风险。

**代码片段:**
```
os.system(f"echo \"export CUDA='{cuda}'\" >> ~/.profile")
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-1BCBEA0D - 不安全的Hugging Face Hub下载（未固定版本）

- **严重等级:** MEDIUM
- **文件位置:** `utils/update_metadata.py:265`
- **数据流:** hf_hub_download函数调用未指定revision参数，导致下载的模型文件版本不可控
- **判断理由:** Bandit静态分析工具检测到第265行调用了hf_hub_download()函数，但没有指定revision参数来固定下载版本。这可能导致下载到恶意或未预期的模型版本，存在供应链攻击风险。

**代码片段:**
```
hf_hub_download()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-70DB0532 - 不安全的Hugging Face Hub下载（未固定版本）

- **严重等级:** MEDIUM
- **文件位置:** `utils/update_metadata.py:286`
- **数据流:** hf_hub_download函数调用未指定revision参数，导致下载的模型文件版本不可控
- **判断理由:** Bandit静态分析工具检测到第286行调用了hf_hub_download()函数，但没有指定revision参数来固定下载版本。这可能导致下载到恶意或未预期的模型版本，存在供应链攻击风险。

**代码片段:**
```
hf_hub_download()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-8A5778A6 - 不安全的Hugging Face Hub下载（未固定版本）

- **严重等级:** MEDIUM
- **文件位置:** `utils/update_metadata.py:295`
- **数据流:** hf_hub_download函数调用未指定revision参数，导致下载的模型文件版本不可控
- **判断理由:** Bandit静态分析工具检测到第295行调用了hf_hub_download()函数，但没有指定revision参数来固定下载版本。这可能导致下载到恶意或未预期的模型版本，存在供应链攻击风险。

**代码片段:**
```
hf_hub_download()
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-97AAF40F - 不安全的Hugging Face Hub下载（未固定版本）

- **严重等级:** HIGH
- **文件位置:** `utils/update_tiny_models.py:126`
- **数据流:** repo_id变量来自第117行的hf_api.list_models()返回的模型ID，经过字符串处理后拼接成repo_id。用户无法直接控制此输入，但攻击者可能通过污染Hugging Face Hub上的模型仓库来影响下载内容。
- **判断理由:** from_pretrained()调用未指定revision参数，将自动下载最新版本的模型。如果模型仓库被恶意更新，将自动获取恶意代码。虽然repo_id来自受信任的组织hf-internal-testing，但未固定版本号仍然存在供应链攻击风险。

**代码片段:**
```
tokenizer_fast = AutoTokenizer.from_pretrained(repo_id)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-581A8541 - 不安全的Hugging Face Hub下载（未固定版本）

- **严重等级:** HIGH
- **文件位置:** `utils/update_tiny_models.py:132`
- **数据流:** 与第126行相同的repo_id来源，仅添加了use_fast=False参数。
- **判断理由:** 同样未指定revision参数，存在与第126行相同的供应链攻击风险。攻击者可能通过更新模型仓库中的tokenizer配置文件来注入恶意代码。

**代码片段:**
```
tokenizer_slow = AutoTokenizer.from_pretrained(repo_id, use_fast=False)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-FC95FF63 - 不安全的Hugging Face Hub下载（未固定版本）

- **严重等级:** HIGH
- **文件位置:** `utils/update_tiny_models.py:138`
- **数据流:** 与第126行相同的repo_id来源。
- **判断理由:** 未指定revision参数，存在供应链攻击风险。攻击者可能通过更新模型仓库中的image processor配置文件来执行恶意操作。

**代码片段:**
```
img_p = AutoImageProcessor.from_pretrained(repo_id)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-4E472C54 - 不安全的Hugging Face Hub下载（未固定版本）

- **严重等级:** HIGH
- **文件位置:** `utils/update_tiny_models.py:144`
- **数据流:** 与第126行相同的repo_id来源。
- **判断理由:** 未指定revision参数，存在供应链攻击风险。攻击者可能通过更新模型仓库中的feature extractor配置文件来执行恶意操作。

**代码片段:**
```
feat_p = AutoFeatureExtractor.from_pretrained(repo_id)
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-AA01F12D - 不安全的YAML反序列化

- **严重等级:** CRITICAL
- **文件位置:** `src/transformers/modelcard.py:1`
- **数据流:** 代码导入了yaml模块，但未指定使用安全的Loader（如SafeLoader）。在后续的from_pretrained等方法中，如果使用yaml.load()加载用户提供的模型卡文件，可能导致任意代码执行。
- **判断理由:** 虽然当前代码片段中未直接调用yaml.load()，但导入了yaml模块且未限制使用安全Loader。在完整的ModelCard类中，from_pretrained方法可能从用户提供的路径加载模型卡文件，如果该文件是YAML格式并使用yaml.load()（默认使用不安全的Loader），攻击者可以构造恶意的YAML文件实现远程代码执行。这是典型的反序列化漏洞。

**代码片段:**
```
import yaml
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-9AD43D10 - 代码注入

- **严重等级:** CRITICAL
- **文件位置:** `src\transformers\agents\python_interpreter.py:1`
- **数据流:** 用户输入 -> evaluate_ast() -> 递归执行AST节点 -> 执行任意Python代码
- **判断理由:** 该文件实现了一个自定义Python解释器，可以执行任意Python代码。虽然使用了ast模块进行解析，但代码中缺乏对危险操作（如文件操作、网络请求、系统命令执行等）的充分限制。攻击者可以通过构造特定的Python代码来绕过安全检查，执行任意系统命令、读写文件、访问网络等危险操作。

**代码片段:**
```
整个文件实现了一个Python解释器，通过ast模块解析和执行Python代码
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-E5958C7C - 不安全的文件操作

- **严重等级:** HIGH
- **文件位置:** `src\transformers\agents\python_interpreter.py:1`
- **数据流:** 用户输入 -> 解释器执行 -> 可能执行文件操作
- **判断理由:** 代码中没有明确禁止文件操作相关的内置函数（如open、read、write等）。攻击者可以通过执行Python代码来读取、写入或删除服务器上的文件，导致严重的安全问题。

**代码片段:**
```
整个解释器执行环境
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---

### VULN-48763817 - 不安全的系统命令执行

- **严重等级:** CRITICAL
- **文件位置:** `src\transformers\agents\python_interpreter.py:1`
- **数据流:** 用户输入 -> 解释器执行 -> 可能执行系统命令
- **判断理由:** 代码中没有限制系统命令执行相关的操作。攻击者可以通过执行Python代码（如使用os.system、subprocess等模块）来执行任意系统命令，完全控制服务器。

**代码片段:**
```
整个解释器执行环境
```

**PoC代码:**
```python
# PoC生成失败: DeepSeek API调用失败，已达最大重试次数
```

---



*报告由 CodeSentinel 自动生成*
