<?php
namespace app\app_api\controller;

use app\core\behavior\UserBehavior;
use service\HookService;
use app\core\util\TokenService;
use service\JsonService;
use service\UtilService;
use think\Config;
use think\Controller;
use app\ebapi\model\user\User;
use think\Hook;


class Basic extends Controller
{
    //是否为调试模式 生产模式下请改为false
    protected $Debug=true;


    protected function _initialize()
    {
        parent::_initialize();
        $this->Debug=Config::get('app_debug');
        header("Access-Control-Allow-Origin:*");
        header("Access-Control-Allow-Methods:POST,GET");
        header("Access-Control-Allow-Headers:*");
    }

    /*
     * 验证token 正确返回userinfo 失败终止程序运行
     * */
    protected function checkTokenGetUserInfo()
    {
        //生产模式非微信内部浏览器禁止访问
        if(!UtilService::isWechatBrowser() && $this->Debug===false) return $this->fail('非法访问');
        //获取白名单跳过token验证
        $check =$this->checkAuth();
        //获取token
        $token =$this->getRequestToken();
        if(!$token && $check===false) $this->fail('请传入token验证您的身份信息');
        //验证token
        $Tokencheck=TokenService::checkToken($token,$check);
        if($Tokencheck===true){
            return ['uid'=>0];
        }else if(is_array($Tokencheck)){
            list($uid)=$Tokencheck;
            $userInfo = User::get($uid);
        }else $this->fail('没有获取到用户信息,请传入token验证您的身份信息',[],402);
        if((!$userInfo || !isset($userInfo)) && $check===false) $this->fail('用户信息获取失败,没有这样的用户!',[],402);
        if(isset($userInfo)){
            if(!$userInfo->status) $this->fail('您已被禁止登录',[],401);
            HookService::listen('init',$userInfo,null,false,UserBehavior::class);
            return $userInfo->toArray();
        }else return ['uid'=>0];
    }



    /*
     * 获取请求token
     * @return string
     * */
    protected function getRequestToken()
    {
        //非生产模式允许把token放在url上传输请求
        if($this->Debug){
            $TOKEN=$this->request->header('token');
        }else{
            $TOKEN =$this->request->get('token','');
            if($TOKEN==='') $TOKEN=$this->request->param('token','');
            if($TOKEN==='') $TOKEN=$this->request->header('token');
        }
        return $TOKEN;
    }
    /*
     * 正确操作返回json
     * @param string | array $msg 提示语或者数据
     * @param array $data 数据
     * @param int $status
     * @return json
     * */
    protected function successful($msg='ok',$data=[],$status=200)
    {
        return JsonService::successful($msg,$data,$status);
    }
    /*
    * 错误操作返回json
    * @param string | array $msg 提示语或者数据
    * @param array $data 数据
    * @param int $status
    * @return json
    * */
    protected function fail($msg='error',$data=[],$status=400)
    {
        return JsonService::fail($msg,$data,$status);
    }
    /*
     * 组装路由
     * @param string $action 方法
     * @param string $controller 控制器
     * @param string $module 模块
     * @return string
     * */
    protected function getAuthName($action,$controller,$module)
    {
        return strtolower($module.'/'.$controller.'/'.$action);
    }

    /*
     * 获取当前的控制器名,模块名,方法名,类名并返回
     * @param string $controller 控制器
     * @param string $module 模块
     * @return string
     * */
    protected function getCurrentController($controller,$module)
    {
        return 'app\\'.$module.'\\controller\\'.str_replace('.','\\',$controller);
    }

    /*
     * 校验器 效验白名单方法跳过token验证
     * @param string $action 方法名
     * @param string $controller 控制器名
     * @param string $module 模块名
     * @return boolean
     * */
    protected function checkAuth($action = null,$controller = null,$module = null)
    {
        //获取当前控制器,模型,方法
        if($module === null) $module = $this->request->module();
        if($controller === null) $controller = $this->request->controller();
        if($action === null) $action = $this->request->action();
        //获取当前访问类名全称
        $className=$this->getCurrentController($controller,$module);
        if(method_exists($className,'whiteList')){
            try{
                //执行白名单方法获取白名单
                $white = $className::whiteList();
                if(!is_array($white)) return false;
                foreach ($white as $actionWhite){
                    //比较白名单和当前访问方法
                    if($this->getAuthName($actionWhite,$controller,$module)==$this->getAuthName($action,$controller,$module))
                        return true;
                }
            }catch (\Exception $e){}
        }
        return false;
    }

}