const btn_menu = document.getElementById("BtnMenu");
const menu = document.getElementById("Menu");
let hide_menu = true;

btn_menu.addEventListener("click", () => {
    if(hide_menu)
    {
        menu.style["display"] = "unset";
        hide_menu = false;
    }
    else
    {
        menu.style["display"] = "none";
        hide_menu = true;
    }
});
