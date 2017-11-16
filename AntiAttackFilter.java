package com.sanxing.epower.core.controller;

import com.sanxing.epower.core.util.GlobalUtil;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/***
 * Injection Attack Filter
 *
 * @author lihuai.chen@163.com
 *
 * This class is for protecting from SQL Injection or XSS Injection;
 *
 * Fileter config shold be added into Web.xml. Config is as follows:
<filter>
<filter-name>injectionAttackFilter</filter-name>
<filter-class>com.sanxing.epower.core.controller.AntiAttackFilter</filter-class>
<init-param>
<param-name>filterClickJack</param-name>
<param-value>true</param-value>
</init-param>
<init-param>
<param-name>filterCSRF</param-name>
<param-value>true</param-value>
</init-param>
<init-param>
<param-name>filterSQLInjectionAndXSS</param-name>
<param-value>true</param-value>
</init-param>
</filter>
<filter-mapping>
<filter-name>injectionAttackFilter</filter-name>
<url-pattern>/*</url-pattern>
</filter-mapping>
 */
public class AntiAttackFilter implements Filter {

    boolean filterSQLInjectionAndXSSOpen = true, filterClickJackingOpen = true, filterCSRFOpen = true;

    @Override
    public void init(FilterConfig config) throws ServletException {
        String filterClickJack = config.getInitParameter("filterClickJack");
        String filterCSRF = config.getInitParameter("filterCSRF");
        String filterSQLInjectionAndXSS = config.getInitParameter("filterSQLInjectionAndXSS");

        filterSQLInjectionAndXSSOpen = new Boolean(filterSQLInjectionAndXSS);
        filterClickJackingOpen = new Boolean(filterClickJack);
        filterCSRFOpen = new Boolean(filterCSRF);
    }

    @Override
    public void destroy() {
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        if (filterCSRFOpen) filterCSRF(servletRequest, servletResponse);
        if (filterClickJackingOpen) filterClickJack(servletResponse);
        if (filterSQLInjectionAndXSSOpen) {
            InjectionAttackWrapper wrapper = new InjectionAttackWrapper((HttpServletRequest) servletRequest);
            filterChain.doFilter(wrapper, servletResponse);
        }
    }

    private static final String X_FRAME_VALUE = "SAMEORIGIN";
    private static final String X_FRAME_HEADER = "X-FRAME-OPTIONS";

    //Prevent to load in iframe for ClickJack Attack
    private void filterClickJack(ServletResponse servletResponse) {
        if (servletResponse instanceof HttpServletResponse) {
            HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;
            if (!httpServletResponse.containsHeader(X_FRAME_HEADER)) {
                httpServletResponse.addHeader(X_FRAME_HEADER, X_FRAME_VALUE);
            }
        }
    }

    //Check CSRF,Check HTTP Header Referer,if it's blank or other host it's forbidden
    private void filterCSRF(ServletRequest servletRequest, ServletResponse servletResponse) throws IOException {
        if (servletResponse instanceof HttpServletResponse && servletRequest instanceof HttpServletRequest) {
            HttpServletResponse response = (HttpServletResponse) servletResponse;
            HttpServletRequest request = (HttpServletRequest) servletRequest;
            String currentURL = request.getRequestURI();
            //Login page no need check
            if (!(currentURL.equals("/") || currentURL.startsWith("/login"))) {
                //After Login begin to check referer
                if (request.getSession().getAttribute(GlobalUtil.CURRENTUSER) != null) {
                    String referer = request.getHeader("referer");
                    if (StringUtils.isBlank(referer) || !referer.contains(request.getServerName())) {
                        response.getOutputStream().write("<script>alert('Forbidden Operation!');window.history.go(-1);</script>".getBytes("utf-8"));
                        response.getOutputStream().close();
                    }
                }
            }
        }
    }
}
