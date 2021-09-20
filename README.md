# 南京大学上网登录脚本（统一身份认证版）

自2021年9月起p.nju.edu.cn改成使用学校的统一身份认证登陆，其本质是一个魔改的~~山寨的~~Authorization Code登陆流程。
令人迷惑的是，学校多个服务（如NJU Box）都可以通过LDAP使用统一身份认证的用户直接登录，上网认证却没用LDAP。

使用本脚本建议搭配cron和DDNS服务使用。

## 使用方法

修改`bras.py`中的登录名和密码。

1. `python3 -m venv venv`并启动virtualenv
2. `pip3 install -r requirements.txt`
3. `python3 bras.py`

