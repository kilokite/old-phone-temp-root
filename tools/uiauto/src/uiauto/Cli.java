package uiauto;

import com.android.uiautomator.core.UiDevice;
import com.android.uiautomator.core.UiObject;
import com.android.uiautomator.core.UiSelector;
import com.android.uiautomator.testrunner.UiAutomatorTestCase;

/**
 * 无 root 情况下的 UI 驱动：MIUI 禁了 adb input，但 UiAutomation 走无障碍注入。
 * 用法：uiautomator runtest uiauto.jar -c uiauto.Cli -e action root
 *       或 -e action menu
 */
public class Cli extends UiAutomatorTestCase {

    public void testMain() throws Exception {
        UiDevice d = getUiDevice();
        String action = getParams().getString("action", "root");

        if ("menu".equals(action)) {
            UiObject more = new UiObject(new UiSelector().description("更多选项"));
            if (!more.exists()) {
                more = new UiObject(new UiSelector().descriptionContains("更多"));
            }
            if (more.exists()) {
                more.click();
                Thread.sleep(600);
            }
            UiObject about = new UiObject(new UiSelector().text("关于"));
            if (about.exists()) about.click();
            Thread.sleep(1200);
            d.pressBack();
            return;
        }

        // 一键获取 Root：按钮在状态卡里，字号大，直接按文字找
        UiObject btn = new UiObject(new UiSelector().text("一键获取 Root"));
        if (!btn.exists()) {
            btn = new UiObject(new UiSelector().textContains("一键获取"));
        }
        if (!btn.exists()) {
            // 可能已经获取过
            return;
        }
        btn.click();
        Thread.sleep(800);

        UiObject start = new UiObject(new UiSelector().text("开始"));
        if (start.exists()) {
            start.click();
        }
    }
}
