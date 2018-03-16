<%@ taglib prefix="security" uri="http://www.springframework.org/security/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@include file="templates/header.jsp"%>
<h1>Index page</h1>
<p>principal: ${principal}</p>
<security:authorize access="isAuthenticated()">you are authenticated <a href="/logout">logout</a></security:authorize>
<form action="save" method="post">
    <input type="text" name="name">
    <input type="text" name="password">
    <input type="submit">
    <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>

</form>
<hr>
<form action="pageNumber">
    <input type="number" name="pageNumber">
    <input type="submit">
</form>
<c:forEach items="${all}" var="user">
    <p>${user}</p>
</c:forEach>

<%@include file="templates/footer.jsp"%>