<?php
// 类库名称：auth权限
// +----------------------------------------------------------------------
// | PHP version 5.6+
// +----------------------------------------------------------------------
// | Copyright (c) 2012-2014 http://www.myzy.com.cn, All rights reserved.
// +----------------------------------------------------------------------
// | Author: 阶级娃儿 <262877348@qq.com> 群：304104682
// +----------------------------------------------------------------------

namespace think;

use think\Config;
use think\Db;
use think\Loader;
use think\Request;
use think\Session;

class Auth
{
    /**
     * @var object 对象实例
     */
    protected static $instance;

    /**
     * @var Request $request Request请求信息对象
     */
    protected $request;

    /**
     * @var object 对象实例
     */
    protected $prefix;

    /**
     * @var is_prefix 请求信息对象
     */
    protected static $is_prefix;
    /**
     * @var array 请求类型
     */
    protected $methods = [
        'GET',
        'POST',
        'PUT',
        'DELETE'
    ];

    /**
     * @var array 配置信息
     */
    protected $configs = [
        // 权限开关
        'auth_on' => true,
        // 认证方式：1为实时认证；每次验证，都重新读取数据库内的权限数据，如果对权限验证非常敏感的，建议使用实时验证;2为登录认证 (即登录成功后，就把该用户用户的权限规则获取并保存到 session，之后就根据 session 值做权限验证判断)
        'auth_type' => 1,
        // 角色用户组数据表名
        'auth_group' => 'auth_group',
        // 用户-角色用户组关系表
        'auth_group_access' => 'auth_group_access',
        // 权限规则表
        'auth_rule' => 'auth_rule',
        // 用户信息表
        'member' => 'member',
    ];

    /**
     * 构造函数
     * @access protected
     */
    public function __construct()
    {
        // 判断是否有设置配置项.此配置项为数组，做一个兼容
        if (Config::has('auth')) {
            // 合并,覆盖配置
            $this->configs = array_merge($this->configs, Config::get('auth'));
        }

        // 初始化request
        $this->prefix = self::prefix();
        // 初始化request
        $this->request = Request::instance();
    }

    /**
     * 初始化
     */
    public static function instance($options = [])
    {
        if (is_null(self::$instance)) {
            self::$instance = new static($options);
        }
        return self::$instance;
    }

    /**
     * 获取表全缀
     */
    public static function prefix()
    {
        if (is_null(self::$is_prefix)) {
            self::$is_prefix = Config::get('database.prefix') ? Config::get('database.prefix') : '';
        }
        return self::$is_prefix;
    }

    /**
     * 检查权限
     * @param $name string|array  需要验证的规则列表,支持逗号分隔的权限规则或索引数组
     * @param $uid  int           认证用户的id
     * @param int $type 认证类型
     * @param string $mode 执行check的模式
     * @param string $relation 如果为 'or' 表示满足任一条规则即通过验证;如果为 'and'则表示需满足所有规则才能通过验证
     * return bool               通过验证返回true;失败返回false
     */
    public function check($name, $uid, $type = 0, $mode = 'url', $relation = 'or')
    {
        if (empty($name) || empty($uid)) {
            return '缺少参数s！';
        }
        if ($this->configs['auth_on'] === false) {
            return true;
        }
        // 获取用户需要验证的所有有效规则列表
        $authList = $this->getAuthList($uid, $type);

        if (is_string($name)) {
            $name = strtolower($name);
            if (strpos($name, ',') !== false) {
                $name = explode(',', $name);
            } else {
                $name = [$name];
            }
        }

        $list = []; //保存验证通过的规则名
        if ('url' == $mode) {
            $REQUEST = unserialize(strtolower(serialize(Request()->param())));
        }
        foreach ($authList as $auth) {
            $query = preg_replace('/^.+\?/U', '', $auth);
            if ('url' == $mode && $query != $auth) {
                parse_str($query, $param); //解析规则中的param
                $intersect = array_intersect_assoc($REQUEST, $param);
                $auth = preg_replace('/\?.*$/U', '', $auth);

                if (in_array($auth, $name) && $intersect == $param) {
                    //如果节点相符且url参数满足
                    $list[] = $auth;
                }
            } else {
                if (in_array($auth, $name)) {
                    $list[] = $auth;
                }
            }
        }

        if ('or' == $relation && !empty($list)) {
            return true;
        }

        $diff = array_diff($name, $list);
        if ('and' == $relation && empty($diff)) {
            return true;
        }
        return false;
    }

    /**
     * 获得权限列表
     * @param integer $uid 用户id
     * @param integer $type
     * return array
     */
    protected function getAuthList($uid, $type)
    {
        static $_authList = []; //保存用户验证通过的权限列表
        $t = implode(',', (array)$type);
        if (isset($_authList[$uid . $t])) {
            return $_authList[$uid . $t];
        }
        // 登录认证 (即登录成功后，就把该用户用户的权限规则获取并保存到 session，之后就根据 session 值做权限验证判断
        if (2 == $this->configs['auth_type'] && Session::has('_auth_list_' . $uid . $t)) {
            return Session::get('_auth_list_' . $uid . $t);
        }
        //读取用户所属用户组
        $groups = $this->getGroups($uid);

        $ids = []; //保存用户所属用户组设置的所有权限规则id
        foreach ($groups as $g) {
            $ids = array_merge($ids, explode(',', trim($g['rules'], ',')));
        }

        $ids = array_unique($ids);
        if (empty($ids)) {
            $_authList[$uid . $t] = [];
            return [];
        }

        $map = [
            'type' => $type,
            'id' => array('in', $ids),
            'status' => 1,
        ];

        //读取用户组所有权限规则
        $rules = Db::name($this->configs['auth_rule'])->where($map)->field('condition,name')->select();

        //循环规则，判断结果。
        $authList = []; //
        foreach ($rules as $rule) {
            // 判断是否有附加规则
            if (!empty($rule['condition'])) {
                $user = $this->getUserInfo($uid); //获取用户信息,一维数组
                $command = preg_replace('/\{(\w*?)\}/', '$user[\'\\1\']', htmlspecialchars_decode($rule['condition']));

                @(eval('$condition=(' . $command . ');'));
                if ($condition) {
                    $authList[] = strtolower($rule['name']);
                }
            } else {
                //只要存在就记录
                $authList[] = strtolower($rule['name']);
            }
        }

        $_authList[$uid . $t] = $authList;

        if (2 == $this->configs['auth_type']) {
            //规则列表结果保存到session
            Session::set('_auth_list_' . $uid . $t, $authList);
        }
        return array_unique($authList);
    }

    /**
     * 根据用户id获取用户组,返回值为数组
     * @param  $uid int     用户id
     * return array       用户所属的用户组 array(
     *     array('uid'=>'用户id','group_id'=>'用户组id','title'=>'用户组名称','rules'=>'用户组拥有的规则id,多个,号隔开'),
     *     ...)
     */

    public function getGroups($uid)
    {
        static $groups = [];
        if (isset($groups[$uid])) {
            return $groups[$uid];
        }

        // 转换表名
        $auth_group_access = Loader::parseName($this->configs['auth_group_access'], 1);
        $auth_group = Loader::parseName($this->configs['auth_group'], 1);

        // 执行查询
        $user_groups = Db::view($auth_group_access, 'member_id,group_id')
            ->view($auth_group, 'name,rules', "{$auth_group_access}.group_id={$auth_group}.id", 'LEFT')
            ->where("{$auth_group_access}.member_id='{$uid}' and {$auth_group}.status='1'")
            ->select();
        $groups[$uid] = $user_groups ?: [];
        return $groups[$uid];
    }

    /**
     * 获得用户资料,根据自己的情况读取数据库
     */
    protected function getUserInfo($uid)
    {
        static $userinfo = [];
        $user = Db::name($this->configs['auth_user']);
        // 获取用户表主键
        $_pk = is_string($user->getPk()) ? $user->getPk() : 'uid';
        if (!isset($userinfo[$uid])) {
            $userinfo[$uid] = $user->where($_pk, $uid)->find();
        }
        return $userinfo[$uid];
    }
}