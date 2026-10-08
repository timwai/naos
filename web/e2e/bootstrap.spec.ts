import { expect, test } from "@playwright/test";

test("admin bootstrap, navigation and logout protect privileged pages", async ({ page }) => {
  await page.goto("/");

  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByText("首次初始化")).toBeVisible();

  await page.getByLabel("用户名").fill("admin");
  await page.getByLabel("密码", { exact: true }).fill("delivery-test-strong-password");
  await page.getByLabel("确认密码").fill("delivery-test-strong-password");
  await page.getByRole("button", { name: "创建管理员并登录" }).click();

  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await page.getByRole("link", { name: "文件", exact: true }).click();
  await expect(page.getByRole("heading", { name: "文件", exact: true })).toBeVisible();

  await page.goto("/settings");
  await expect(page.getByRole("heading", { name: "设置与诊断" })).toBeVisible();

  await page.getByRole("button", { name: "退出登录" }).click();
  await expect(page).toHaveURL(/\/login$/);
  await page.goto("/settings");
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByRole("button", { name: "登录", exact: true })).toBeVisible();
});
