# C1SEC 社团网站

基于 [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/) 构建，
通过 GitHub Actions 自动部署到 GitHub Pages。

## 项目结构

```
.
├── docs/                     # 站点内容（全部是 Markdown）
│   ├── index.md              # 首页（社团介绍）
│   ├── cognition/            # 认知篇（学习本身 / 降低预期 / 提问的艺术 / HTB 子板块）
│   ├── resources/            # 资源篇（CTF / 渗透技能 / 证书 / 漏洞挖掘 / 计算机方向）
│   ├── infra/                # 基建篇（电脑、笔记、Git、环境、编程……）
│   └── training/             # 培训计划表（按周次）
├── mkdocs.yml                # 站点配置（主题、导航、插件）
├── requirements.txt          # Python 依赖
└── .github/workflows/deploy.yml   # push 到 main 时自动构建并发布
```

顶部横向 tab = `nav` 的一级条目；侧边栏的文件夹可展开/收起，点击文件夹标题
（如「认知篇」「HTB《Learning Process》」）会进入该板块的 index 页。
新增页面后，记得在 `mkdocs.yml` 的 `nav` 中登记。

## 本地开发

```bash
# 首次：创建并激活虚拟环境（已创建过 .venv 可跳过创建）
python -m venv .venv
source .venv/Scripts/activate        # Windows Git Bash
# .venv\Scripts\activate             # Windows PowerShell

pip install -r requirements.txt

# 启动本地预览，浏览器打开 http://127.0.0.1:8000
mkdocs serve
```

不激活虚拟环境也可以直接用 `.venv/Scripts/mkdocs serve`。

## 写作

- 新增普通页面：在 `docs/` 下新建 `.md` 文件，并在 `mkdocs.yml` 的 `nav` 中登记。
- 新增培训周次：复制 `docs/training/week-01.md`（含阅读材料 / 视频链接 / 作业三个小节）为
  `week-02.md` 等，在 `mkdocs.yml` 的 `nav` → `培训计划表` 下登记一行。

## 部署步骤（组织 GitHub Pages）

1. **改配置**：编辑 `mkdocs.yml`，取消注释并修改
   `site_url` / `repo_url` / `repo_name`（以及 `site_name`、`copyright` 中的社团名）。
2. **建仓库**：在组织下创建仓库（如 `org/c1sec`），本目录已 `git init`，只需：

   ```bash
   git remote add origin git@github.com:<组织名>/<仓库名>.git
   git add -A
   git commit -m "init: 社团站点"
   git push -u origin main
   ```

3. **开启 Pages**：仓库 **Settings → Pages → Build and deployment → Source**
   选择 **GitHub Actions**（仅需设置一次）。
4. push 到 `main` 后，Actions 会自动构建并发布到
   `https://<组织名>.github.io/<仓库名>/`；也可在 Actions 页面手动触发
   `Deploy to GitHub Pages`。

> 注意：CI 使用 `mkdocs build --strict`，文档有警告（如失效链接）会导致构建失败，
> 本地可先跑 `.venv/Scripts/mkdocs build --strict` 自查。
