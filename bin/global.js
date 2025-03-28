document.addEventListener("DOMContentLoaded", function () {
    const navItems = document.querySelectorAll(".main-nav ul li");
  
    navItems.forEach((item) => {
      item.addEventListener("click", function () {
        // すべての li から active クラスを削除
        navItems.forEach((nav) => nav.classList.remove("active"));
  
        // クリックした li に active クラスを追加
        this.classList.add("active");
      });
    });
  });
  