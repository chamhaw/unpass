# unpass - 企业级密码审计工具

## 概述
UnPass是一个专注于2FA和Passkey检测的密码审计工具，使用权威数据源帮助识别密码库中的安全改进机会。

## 功能特性
- 🔐 **2FA支持检测**：基于3000+网站的权威数据库，识别支持2FA但未启用的网站
- 🔐 **Passkey支持检测**：基于238+网站的权威数据库，识别支持Passkey但仍用传统密码的网站
- 📊 **详细元数据**：提供支持的认证方法、设置链接、官方文档等详细信息

## 数据源
- **2FA数据库**: 3,302个网站的2FA支持信息，包含支持的认证方法和官方文档链接
- **Passkey数据库**: 238个网站的Passkey支持信息，包含设置链接和分类信息
- **数据更新**: 定期更新以确保检测准确性

## 安装

### 从源码构建
```bash
git clone <repository-url>
cd unpass
make build
```

### 系统要求
- Go 1.24+
- 检测数据库文件（database目录）

## 使用方法

### 基本审计
```bash
# 基础审计（使用默认database目录）
./bin/unpass audit -f demo.json

# 指定数据库路径
./bin/unpass audit -f demo.json -d /path/to/database

# 输出到文件
./bin/unpass audit -f demo.json -o report.json
```

### 支持的数据格式
支持JSON格式的密码数据：
```json
[
  {
    "id": "1",
    "title": "GitHub Account", 
    "url": "https://github.com",
    "username": "user@example.com",
    "password": "your-password",
    "notes": "Development account",
    "tags": ["work", "development"]
  }
]
```

## 架构设计
采用数据驱动的模块化设计：

### 目录结构
```
unpass/
├── cmd/cli/              # 命令行工具
├── internal/
│   ├── audit/            # 审计引擎
│   ├── detector/         # 检测模块
│   │   ├── twofa.go      # 2FA检测器
│   │   └── passkey.go    # Passkey检测器
│   ├── database/         # 数据库加载器
│   ├── parser/           # JSON解析器
│   ├── report/           # JSON报告生成
│   └── types/            # 数据类型定义
├── database/             # 权威数据库
│   ├── 2fa_database.json        # 2FA支持数据库
│   ├── passkey_database.json    # Passkey支持数据库
│   └── pwned_passwords_database.json # 泄露密码数据库
├── configs/              # 配置文件
└── testdata/             # 测试数据
```

### 核心组件
- **数据库加载器**: 加载和解析权威数据源
- **2FA检测器**: 基于3,302个网站的权威数据库检测2FA支持
- **Passkey检测器**: 基于238个网站的权威数据库检测Passkey支持
- **JSON解析器**: 解析密码数据
- **JSON报告**: 输出详细检测结果

## 开发

### 构建项目
```bash
make build    # 构建二进制文件
make test     # 运行测试
make clean    # 清理构建文件
```

## 示例输出

### 增强的检测结果
```json
{
  "results": [
    {
      "credential_id": "1",
      "type": "missing_2fa",
      "severity": "medium", 
      "message": "Website supports 2FA but may not be enabled",
      "metadata": {
        "domain": "github.com",
        "url": "https://github.com",
        "supported_methods": ["sms", "totp", "custom-software", "u2f"],
        "documentation_url": "https://docs.github.com/en/github/authenticating-to-github/..."
      }
    },
    {
      "credential_id": "1",
      "type": "missing_passkey",
      "severity": "medium",
      "message": "Website supports Passkey but traditional password is still used",
      "metadata": {
        "domain": "github.com",
        "site_name": "GitHub",
        "support_type": "signin",
        "setup_link": "https://github.com/settings/security",
        "category": "Information Technology"
      }
    }
  ],
  "summary": {
    "total_credentials": 5,
    "issues_found": 5,
    "by_type": {
      "missing_2fa": 3,
      "missing_passkey": 2
    }
  }
}
```

## 数据库更新

检测数据库定期更新以确保准确性：
- **2FA数据库**: 包含主流网站的2FA支持状态和方法
- **Passkey数据库**: 跟踪最新的Passkey采用情况
- **更新频率**: 建议定期更新数据库文件以获得最佳检测效果