# Project Style Guide

本文档总结了 Elkeid 仓库（主要针对 `server/manager` 后端服务）的代码风格、架构模式和开发规范。

## 1. 包组织结构 (Package Organization)

后端服务主要位于 `server/manager` 目录下，采用分层架构：

- **`biz/`**: 业务逻辑层
  - **`handler/`**: API 处理器，按版本组织 (e.g., `v0`, `v1`, `v6`)。核心业务逻辑通常直接位于此处。
  - **`midware/`**: HTTP 中间件 (Auth, Metrics 等)。
  - **`common/`**: 通用工具、常量、错误码定义。
  - **`router.go`**: 路由注册入口。
- **`infra/`**: 基础设施层
  - **`ylog/`**: 日志库封装 (基于 zap)。
  - **`def/`**: 跨层共享的结构体定义。
  - **`mongodb/`, `redis/`, `kafka/`**: 各类基础组件的客户端初始化代码。
- **`internal/`**: 内部模块 (e.g., `atask`, `asset_center`)。

## 2. 命名规范 (Naming Conventions)

### 文件命名
- **Go 文件**: 存在不一致情况。
  - 推荐使用 **snake_case** (e.g., `router.go`, `task.go`)。
  - 现有代码中包含 camelCase (e.g., `akskAuth.go`)，建议新文件遵循 snake_case。

### 代码命名
- **函数 (Functions)**: Exported 函数使用 **PascalCase** (e.g., `GetTaskList`)。
- **变量 (Variables)**: 局部变量使用 **camelCase** (e.g., `pageRequest`)。
- **结构体 (Structs)**: 使用 **PascalCase** (e.g., `TaskDetail`)。
- **接口 (Interfaces)**: 使用 **PascalCase**。

### API 路由命名
- **路由路径**: 存在版本差异，风格不统一。
  - **v1**: 主要使用 **camelCase** (e.g., `/createTask/ctrl`)。
  - **v6**: 主要使用 **PascalCase** (e.g., `/GetTaskList`, `/DescribeHosts`)。
  - **Group**: 部分使用 **kebab-case** (e.g., `/asset-center`)。
- **建议**: 新增接口应遵循当前版本的既定风格（v6 倾向于 PascalCase），但长期建议统一为 kebab-case 或 camelCase。

### 字段 Tag
- **JSON**: 使用 **snake_case** (e.g., `json:"task_id"`).
- **BSON**: 使用 **snake_case** (e.g., `bson:"task_id"`).

## 3. 错误处理模式 (Error Handling)

- **检查方式**: 显式检查 `if err != nil`。
- **日志记录**: 在错误发生处立即记录，通常包含上下文信息（如函数名）。
  ```go
  ylog.Errorf("FunctionName", err.Error())
  ```
- **响应返回**: 使用 `common.CreateResponse` 统一封装错误响应。
  ```go
  common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
  ```
- **错误码**: 定义在 `server/manager/biz/common` 中 (e.g., `ParamInvalidErrorCode`, `DBOperateErrorCode`)。

## 4. 日志使用方式 (Logging)

- **库**: 使用 `server/manager/infra/ylog` (封装自 uber-go/zap)。
- **级别**: `Infof`, `Errorf`, `Warnf`, `Debugf`。
- **格式**: 第一个参数通常为 **Context/Tag** (如函数名或模块名)，第二个参数为格式化字符串。
  ```go
  // 签名: func Infof(msg string, format string, v ...interface{})
  ylog.Infof("[CreateSyncConfigTask]", "receive request body: %+v", body)
  ```

## 5. 中间件结构 (Middleware)

- **位置**: `server/manager/biz/midware/`。
- **实现**: 标准 `gin.HandlerFunc`。
- **应用**: 在 `server/manager/biz/router.go` 中通过 `r.Use()` 或 `group.Use()` 注册。
- **常见中间件**:
  - `Metrics()`: 监控指标。
  - `TokenAuth()`, `AKSKAuth()`, `RBACAuth()`: 认证与鉴权。

## 6. 依赖注入方式 (Dependency Injection)

- **模式**: **无依赖注入 (No DI)**。采用 **全局单例 (Global Singleton)** 模式。
- **实现**:
  - 基础设施客户端（如 MongoDB, Redis）在 `infra` 包初始化时创建全局变量。
  - 业务代码直接引用全局变量 (e.g., `infra.MongoClient`)。
  - 日志器也是全局单例 (`ylog.defaultLogger`)。

## 7. DTO / Model 分层方式

- **Request/Response DTO**:
  - 通常直接定义在 Handler 函数内部或同一文件中。
  - 命名通常为 `XxxRequest`, `XxxResponse` 或 `XxxDetail`。
- **Database Model**:
  - 经常与 DTO 混用。Request 结构体常包含 `bson` tag，直接用于数据库查询构建。
  - 这种模式减少了样板代码，但导致 API 层与数据库层耦合较紧。
- **Shared Models**:
  - 跨模块复用的结构体定义在 `server/manager/infra/def` 或 `biz/common`。

## 8. 典型函数结构风格

Handler 函数通常遵循以下流程：

1.  **绑定参数**: 使用 `c.BindJSON` 或 `c.BindQuery` 将请求绑定到结构体。
2.  **参数校验**: 检查参数有效性，失败则记录日志并返回 `ParamInvalidErrorCode`。
3.  **业务/数据逻辑**:
    - 构建查询条件 (BSON map)。
    - 直接调用 `infra.MongoClient` 执行数据库操作。
    - 处理游标或结果集。
4.  **返回响应**: 调用 `common.CreateResponse` 返回结果。

```go
func ExampleHandler(c *gin.Context) {
    // 1. Bind
    var req RequestStruct
    if err := c.BindJSON(&req); err != nil {
        // 2. Validate & Log
        ylog.Errorf("ExampleHandler", err.Error())
        common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
        return
    }

    // 3. Logic & DB
    collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.CollectionName)
    // ... db operations ...

    // 4. Response
    common.CreateResponse(c, common.SuccessCode, data)
}
```
