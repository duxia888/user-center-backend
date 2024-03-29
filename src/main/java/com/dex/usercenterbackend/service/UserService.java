package com.dex.usercenterbackend.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.dex.usercenterbackend.model.domain.User;

import javax.servlet.http.HttpServletRequest;

/**
 * 用户服务
 *
 * @author axin
 * @description 针对表【user】的数据库操作Service
 * @createDate 2024-02-07 16:55:39
 */
public interface UserService extends IService<User> {

    /**
     * 用户注册
     *
     * @param userAccount   用户账户
     * @param userPassword  用户密码
     * @param checkPassword 校验密码
     * @return 新用户id
     */

    long userRegister(String userAccount, String userPassword, String checkPassword);

    /**
     * 用户登录
     *
     * @param userAccount  用户账户
     * @param userPassword 用户密码
     * @param request 请求体
     * @return 脱敏后的用户信息
     */
    User userLogin(String userAccount, String userPassword, HttpServletRequest request);

    /**
     * 用户脱敏
     *
     * @param orignUser 传进来的用户
     * @return 脱敏后的用户信息
     */
    User getSafetyUser(User orignUser);

    /**
     * 用户注销
     *
     * @param request 请求
     */
    int userLogout(HttpServletRequest request);
}
