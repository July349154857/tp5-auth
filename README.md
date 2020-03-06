# tp5-auth
tp5权限
这是一个基于ThinkPHP5框架的Auth类库

# 安装
composer require misterliu/tp5-auth

#认证原理
认证规则表 （think_auth_rule）
认证用户组表 (think_auth_group)
认证用户组授权权限表（think_auth_group_access）
我们在认证规则表中定义权限规则， 在认证用户组表中定义每个用户组有哪些权限规则，在认证用户组授权权限表中定义用户所属的用户组。

#配置文件
将目录下config/auth.php配置文件复制到TP5框架配置文件目录

return [
	
	// SESSION识别标识
	'auth_session'      => '自定义',   
	// 是否开启测试数据操作           	
	'show_testdata'     => false,                      	
	// 认证开关
	'auth_on'           => true,           
	// 认证方式，1为实时认证；2为登录认证。           					
	'auth_type'         => 1,    
	// 用户组数据表名                     					
	'auth_group'        => 'auth_group',   
	// 用户-用户组关系表     				    
	'auth_group_access' => 'auth_group_access', 	
	// 权限规则表				
	'auth_rule'         => 'auth_rule',        
	// 用户信息表 					
	'auth_user'         => 'member',             					
];

#数据库建立

>
	DROP TABLE IF EXISTS `s_auth_group`;
    CREATE TABLE `s_auth_group`  (
      `id` mediumint(8) UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '分组ID',
      `name` char(100) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '分组名称',
      `description` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '角色描述',
      `status` tinyint(1) UNSIGNED NOT NULL DEFAULT 1 COMMENT '分组状态',
      `rules` char(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '节点',
      `create_time` int(10) UNSIGNED NOT NULL COMMENT '创建时间',
      `update_time` int(10) UNSIGNED NOT NULL COMMENT '更新时间',
      PRIMARY KEY (`id`) USING BTREE
    ) ENGINE = InnoDB AUTO_INCREMENT = 6 CHARACTER SET = utf8 COLLATE = utf8_general_ci COMMENT = '角色表' ROW_FORMAT = Dynamic;
    
    DROP TABLE IF EXISTS `s_auth_group_access`;
    CREATE TABLE `s_auth_group_access`  (
      `member_id` mediumint(8) UNSIGNED NOT NULL COMMENT '用户ID',
      `group_id` mediumint(8) UNSIGNED NOT NULL COMMENT '分组ID',
      UNIQUE INDEX `uid_group_id`(`member_id`, `group_id`) USING BTREE,
      INDEX `uid`(`member_id`) USING BTREE,
      INDEX `group_id`(`group_id`) USING BTREE
    ) ENGINE = InnoDB CHARACTER SET = utf8 COLLATE = utf8_general_ci COMMENT = '角色节点关联表' ROW_FORMAT = Dynamic;
    
    DROP TABLE IF EXISTS `s_auth_rule`;
    CREATE TABLE `s_auth_rule`  (
      `id` mediumint(8) UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '节点ID',
      `name` char(80) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '节点名称',
      `title` char(20) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '节点标题',
      `type` tinyint(1) UNSIGNED NOT NULL DEFAULT 0 COMMENT '认证类型 0',
      `node_icon` varchar(32) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '节点图标',
      `class_icon` varchar(32) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '分类图标',
      `status` tinyint(1) UNSIGNED NOT NULL DEFAULT 1 COMMENT '节点状态',
      `condition` char(100) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '节点规则',
      `sort` smallint(6) UNSIGNED NOT NULL DEFAULT 0 COMMENT '排序',
      `pid` smallint(6) UNSIGNED NOT NULL COMMENT '父级ID',
      `level` tinyint(1) UNSIGNED NOT NULL COMMENT '模块级别',
      `create_time` int(10) UNSIGNED NOT NULL COMMENT '更新时间',
      `update_time` int(10) UNSIGNED NOT NULL,
      PRIMARY KEY (`id`) USING BTREE,
      UNIQUE INDEX `name`(`name`) USING BTREE
    ) ENGINE = InnoDB AUTO_INCREMENT = 27 CHARACTER SET = utf8 COLLATE = utf8_general_ci COMMENT = '操作节点表' ROW_FORMAT = Dynamic;
    
#代码举例
    public function test(){

        $auth = new Auth();
        $url = request()->module().'/'.request()->controller().'/'.request()->action();
        $admin = $auth->check($url,1);// booleans
        halt($admin);
    }           					
    
    第三个参数指定为"and 或 or" and表示同时成立时才返回true。or其中一条规则成立都返回true
    
    condition字段是规则条件，默认为空 表示没有附加条件
    例：{points}<100 这里 {points} 表示 think_members 表 中字段 points 的值。


