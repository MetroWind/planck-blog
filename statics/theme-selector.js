function selectTheme(new_theme)
{
    fetch(SELECT_THEME_ENDPOINT, {
        method: "POST",
        body: JSON.stringify({theme: new_theme})
    }).then((_) => location.reload());
}

const theme_selector = document.getElementById("SelectTheme");
theme_selector.addEventListener("change", () => selectTheme(theme_selector.value));
