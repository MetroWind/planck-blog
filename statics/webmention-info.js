const webmention_info_toggle =
    document.getElementById("WebmentionInfoToggle");
const webmention_info = document.getElementById("WebmentionInfo");
const ANIMATION_DURATION_MS = 180;

function showWebmentionInfo()
{
    webmention_info.hidden = false;
    webmention_info.getBoundingClientRect();
    webmention_info.classList.add("is-expanded");
}

function hideWebmentionInfo()
{
    if(!webmention_info.classList.contains("is-expanded"))
    {
        webmention_info.hidden = true;
    }
}

function toggleWebmentionInfo(event)
{
    event.preventDefault();
    const is_expanded = !webmention_info.classList.contains("is-expanded");

    if(is_expanded)
    {
        showWebmentionInfo();
    }
    else
    {
        webmention_info.classList.remove("is-expanded");
        setTimeout(hideWebmentionInfo, ANIMATION_DURATION_MS);
    }

    webmention_info_toggle.setAttribute("aria-expanded", String(is_expanded));
}

if(webmention_info_toggle && webmention_info)
{
    webmention_info_toggle.addEventListener("click", toggleWebmentionInfo);
}
