<?php
namespace  routine;

use Think\Model;
/**
 * 小程序token辅助验证表
 * Class Token
 */
class Token extends Model
{
    use ModelTrait;

    /*
     * 保存随机字符串 当前用户有token则删除 保存最新token
     * @param int $uid 用户uid
     * @param string $randstring 随机字符串
     * @return array
     * */
    public static function SetRandString($uid,$randstring)
    {
        if(self::find(['uid'=>$uid])) self::where('uid',$uid)->delete();
        return self::insert(['uid'=>$uid,'rand_string'=>$randstring,'add_time'=>time()]);
    }

    /*
     * 验证当前token是否被篡改
     * @param int $uid 用户uid
     * @param string $randstring 随机字符串
     * @return Boolean
     * */
    public static function checkRandString($uid,$randstring)
    {
        return self::where('uid',$uid)->value('rand_string') === $randstring;
    }
}