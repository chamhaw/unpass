# UnPass 密码管理器

一个基于现代Android架构组件构建的安全密码管理器应用。

## 🔒 核心特性

### 安全性
- **端到端加密**: 采用AES-256加密算法保护所有数据
- **多因素认证**: 支持主密码 + 生物识别认证
- **零知识架构**: 应用无法访问用户的明文密码
- **硬件安全模块**: 利用Android Keystore保护密钥
- **数据库加密**: 使用SQLCipher加密本地数据库

### 功能特性
- 安全的密码存储和管理
- 强密码生成器
- 生物识别快速解锁
- 密码强度分析
- 数据导入/导出
- 自动锁定机制
- 密码泄露检测

## 🏗️ 架构设计

### 模块化架构
项目采用多模块架构，确保代码的可维护性和可扩展性：

```
app/                    # 主应用模块
├── core-security/      # 核心安全模块
├── core-database/      # 数据库核心模块
├── core-crypto/        # 加密核心模块
├── core-ui/           # UI核心模块
├── feature-auth/      # 认证功能模块
├── feature-vault/     # 密码库功能模块
├── feature-settings/  # 设置功能模块
└── feature-export/    # 导入导出功能模块
```

### 技术栈
- **UI框架**: Jetpack Compose + Material 3
- **架构组件**: MVVM + Repository Pattern
- **依赖注入**: Dagger Hilt
- **数据库**: Room + SQLCipher
- **网络**: Retrofit + OkHttp
- **安全**: Android Keystore + Biometric API
- **加密**: Bouncy Castle + Android Security Crypto
- **测试**: JUnit + Mockk + Espresso

## 🛠️ 开发环境

### 系统要求
- Android Studio Hedgehog | 2023.1.1 或更高版本
- JDK 11 或更高版本
- Android SDK API 24+ (Android 7.0)
- Kotlin 1.9.10+

### 构建项目
```bash
# 克隆项目
git clone https://github.com/yourusername/unpass.git
cd unpass

# 构建项目
./gradlew build

# 运行测试
./gradlew test

# 安装到设备
./gradlew installDebug
```

## 📱 支持的Android版本
- **最低支持版本**: Android 7.0 (API 24)
- **目标版本**: Android 14 (API 34)
- **推荐版本**: Android 10+ (API 29+) 以获得最佳安全特性

## 🔧 配置说明

### 构建变体
- **debug**: 开发调试版本，包含调试信息
- **release**: 生产发布版本，启用代码混淆和优化

### 签名配置
生产环境需要配置签名密钥，请在 `app/build.gradle.kts` 中配置：

```kotlin
android {
    signingConfigs {
        release {
            storeFile file("path/to/your/keystore.jks")
            storePassword "your_store_password"
            keyAlias "your_key_alias"
            keyPassword "your_key_password"
        }
    }
}
```

## 🧪 测试

### 运行测试
```bash
# 单元测试
./gradlew test

# 集成测试
./gradlew connectedAndroidTest

# 代码覆盖率
./gradlew jacocoTestReport
```

### 代码质量
```bash
# 代码质量检查
./gradlew detekt

# 代码格式化
./gradlew ktlintFormat

# 所有检查
./gradlew check
```

## 🚀 部署

### 构建发布版本
```bash
./gradlew assembleRelease
```

### 生成AAB包
```bash
./gradlew bundleRelease
```

## 📋 开发指南

### 代码规范
- 遵循 [Kotlin 编码规范](https://kotlinlang.org/docs/coding-conventions.html)
- 使用 [ktlint](https://ktlint.github.io/) 进行代码格式化
- 使用 [detekt](https://detekt.dev/) 进行静态代码分析

### 提交规范
```bash
# 功能开发
git commit -m "feat: 添加密码强度检测功能"

# 问题修复
git commit -m "fix: 修复生物识别认证失败问题"

# 文档更新
git commit -m "docs: 更新README文档"
```

### 分支策略
- `main`: 主分支，稳定的生产代码
- `develop`: 开发分支，集成所有新功能
- `feature/*`: 功能分支，开发新功能
- `hotfix/*`: 热修复分支，修复紧急问题

## 🔐 安全注意事项

### 开发环境
- 不要在代码中硬编码密钥或敏感信息
- 使用环境变量或安全配置文件存储敏感配置
- 定期更新依赖库以修复安全漏洞

### 生产环境
- 启用代码混淆和优化
- 使用强密码保护签名密钥
- 定期进行安全测试和漏洞扫描
- 建立安全事件响应机制

## 📄 许可证

本项目采用 MIT 许可证，详情请参阅 [LICENSE](LICENSE) 文件。

## 🤝 贡献

欢迎提交问题和功能请求！请查看 [CONTRIBUTING.md](CONTRIBUTING.md) 了解详细信息。

### 贡献者
- [@yourusername](https://github.com/yourusername) - 项目维护者

## 📞 联系我们

- 问题报告: [GitHub Issues](https://github.com/yourusername/unpass/issues)
- 功能请求: [GitHub Discussions](https://github.com/yourusername/unpass/discussions)
- 邮件联系: unpass@example.com

## 📋 更新日志

### [1.0.0] - 2024-01-01
- 初始版本发布
- 基础密码管理功能
- 生物识别认证
- 密码生成器
- 数据导入导出

## 🙏 致谢

感谢所有开源社区的贡献者和以下项目的支持：
- [Android Jetpack](https://developer.android.com/jetpack)
- [Jetpack Compose](https://developer.android.com/jetpack/compose)
- [Dagger Hilt](https://dagger.dev/hilt/)
- [Room](https://developer.android.com/training/data-storage/room)
- [SQLCipher](https://www.zetetic.net/sqlcipher/)
- [Bouncy Castle](https://www.bouncycastle.org/)

---

**安全提醒**: 请定期备份您的密码数据，并确保记住您的主密码。我们无法帮助您恢复遗忘的主密码。 