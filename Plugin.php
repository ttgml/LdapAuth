<?php

namespace TypechoPlugin\LdapAuth;

use Typecho\Plugin\PluginInterface;
use Typecho\Widget\Helper\Form;
use Typecho\Widget\Helper\Form\Element\Checkbox;
use Typecho\Widget\Helper\Form\Element\Text;
use Widget\Options;
use Widget\User;
use Typecho\Db;
use Typecho\Common;
use Utils\PasswordHash;

if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}
/**
 * LdapAuth
 *
 * @package LdapAuth
 * @author zxcv
 * @version 0.0.1
 * @link https://sout.ltd
 */
class Plugin implements PluginInterface
{
    /**
     * 激活插件方法,如果激活失败,直接抛出异常
     */
    public static function activate()
    {
        //\Typecho\Plugin::factory('admin/menu.php')->navBar = __CLASS__ . '::render';
        \Typecho\Plugin::factory('Widget\User')->login = __CLASS__ . '::login';
    }

    /**
     * 禁用插件方法,如果禁用失败,直接抛出异常
     */
    public static function deactivate()
    {
    }

    /**
     * 获取插件配置面板
     *
     * @param Form $form 配置面板
     */
    public static function config(Form $form)
    {
        $ldap_server = new Text('ldap_server', null, 'ldap://example.com', _t('LDAP server'));
        $ldap_root_dn = new Text('ldap_root_dn', null, "dc=example,dc=com", _t('root DN'));
        $ldap_user_search_base = new Text('ldap_user_search_base', null, 'ou=people', _t('User search base'));
        $ldap_user_search_filter = new Text('ldap_user_search_filter', null, 'uid=$username', _t('User search filter'));
        $advanced_options = new Checkbox('advanced_options', [
            'reg' => _t('Create a new account when the logged-in user does not exist'),
            'idb' => _t('Use built-in authentication when ldap is not available')
        ], ['reg','idb'], _t('Extended Settings'));
        $form->addInput($ldap_server);
        $form->addInput($ldap_root_dn);
        $form->addInput($ldap_user_search_base);
        $form->addInput($ldap_user_search_filter);
        $form->addInput($advanced_options->multiMode());
    }

    /**
     * 个人用户的配置面板
     *
     * @param Form $form
     */
    public static function personalConfig(Form $form)
    {
    }

    /**
     * 插件实现方法
     *
     * @access public
     * @return void
     */
    public static function render()
    {
        echo '<span class="message success">'
            . htmlspecialchars(Options::alloc()->plugin('LdapAuth')->word)
            . '</span>';
    }

    public static function login($name, $password, $temporarily, $expire)
    {
        $ldap_server = Options::alloc()->plugin('LdapAuth')->ldap_server;
        $ldap_root_dn = Options::alloc()->plugin('LdapAuth')->ldap_root_dn;
        $ldap_user_search_base = Options::alloc()->plugin('LdapAuth')->ldap_user_search_base;
        $ldap_user_search_filter = Options::alloc()->plugin('LdapAuth')->ldap_user_search_filter;
        $advanced_options = Options::alloc()->plugin('LdapAuth')->advanced_options;

        // 拼接出用户的搜索路径
        $auth_user = str_replace('$username', $name, $ldap_user_search_filter);
        $user_dn = $auth_user . ',' . $ldap_user_search_base . ',' . $ldap_root_dn;

        // 创建连接
        $ldap_conn = ldap_connect($ldap_server);
        // 使用ldap v3
        ldap_set_option($ldap_conn, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($ldap_conn, LDAP_OPT_NETWORK_TIMEOUT, 5);

        $db = Db::get();

        if ($ldap_conn) {
            $ldap_bind = ldap_bind($ldap_conn, $user_dn, $password);
            $errno = ldap_errno($ldap_conn);
            // 密码错误时
            if ($errno == 49) {
                return false;
            }
            // 验证成功时
            if ($errno == 0) {
                $ldap_search = ldap_search($ldap_conn, $user_dn, "uid=$name");
                $ldap_entries = ldap_get_entries($ldap_conn, $ldap_search);
                $ldap_user= $ldap_entries[0]['uid'][0];
                //判断用户是否存在
                if ($ldap_user) {
                    $ldap_user_dn = $ldap_entries[0]['dn'];
                    $ldap_user_email = $ldap_entries[0]['mail'][0];
                    $ldap_user_name = $ldap_entries[0]['cn'][0];
                    $ldap_user_uid = $ldap_entries[0]['uid'][0];
                }

                // 查询用户名是否存在数据库中
                $user = $db ->fetchRow($db->select()
                    ->from('table.users')
                    ->where((strpos($name, '@') ? 'mail' : 'name') . ' = ?', $name)
                    ->limit(1));

                if (empty($user)) {
                    if (in_array('reg', $advanced_options)) {
                        $dataStruct = [
                            'name' => $ldap_user_uid,
                            'mail' => $ldap_user_email,
                            'screenName' => $ldap_user_name,
                            'group' => 'subscriber'
                        ];
                        $insert_sql = $db->insert('table.users')->rows($dataStruct);
                        $insertId = $db->query($insert_sql);
                        $user = $db->fetchRow($db->select()->from('table.users')
                            ->where('uid = ?', $insertId)
                            ->limit(1));
                    } else {
                        return false;
                    }
                }
                if (!$temporarily) {
                    User::alloc() -> commitLogin($user, $expire);
                }

                /** 压入数据 */
                User::alloc()->push($user);
                User::alloc()->currentUser = $user;
                User::alloc()->hasLogin = true;
                User::alloc()::pluginHandle()->loginSucceed(User::alloc(), $name, $password, $temporarily, $expire);
                
                return true;
            }
            // 无法连接时
            if ($errno == -1 ) {
                if (in_array('idb', $advanced_options)){
                    $user = $db->fetchRow($db->select()
                        ->from('table.users')
                        ->where((strpos($name, '@') ? 'mail' : 'name') . ' = ?', $name)
                        ->limit(1));
                    if (empty($user)) {
                        return false;
                    }
                    $hashValidate = User::pluginHandle()->trigger($hashPluggable)->hashValidate($password, $user['password']);
                    if (!$hashPluggable) {
                        if ('$P$' == substr($user['password'], 0, 3)) {
                            $hasher = new PasswordHash(8, true);
                            $hashValidate = $hasher->checkPassword($password, $user['password']);
                        } else {
                            $hashValidate = Common::hashValidate($password, $user['password']);
                        }
                    }
                    if ($user && $hashValidate) {
                        if (!$temporarily) {
                            User::alloc()->commitLogin($user, $expire);
                        }
                        User::alloc()->push($user);
                        User::alloc()->currentUser = $user;
                        User::alloc()->hasLogin = true;
                        User::alloc()::pluginHandle()->loginSucceed(User::alloc(), $name, $password, $temporarily, $expire);
                        return true;
                    }
                }
            }
        }
        User::alloc()->pluginHandle()->loginFailed($name, $password, $temporarily, $expire);
        return false;
    }
}