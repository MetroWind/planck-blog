#include "html_sanitizer.hpp"

#include <algorithm>
#include <cctype>
#include <set>
#include <string_view>
#include <vector>

#include <mw/utils.hpp>
#include <string.h>
#include <tidy.h>
#include <tidybuffio.h>

namespace
{

std::string htmlEscape(const std::string& str)
{
    std::string esc;
    for(char c : str)
    {
        switch(c)
        {
        case '&':
            esc += "&amp;";
            break;
        case '\"':
            esc += "&quot;";
            break;
        case '\'':
            esc += "&#39;";
            break;
        case '<':
            esc += "&lt;";
            break;
        case '>':
            esc += "&gt;";
            break;
        default:
            esc += c;
            break;
        }
    }
    return esc;
}

void sanitizeAST(TidyDoc tdoc, TidyNode tnod)
{
    if(!tnod)
    {
        return;
    }

    // Discard dangerous tags
    TidyNodeType type = tidyNodeGetType(tnod);
    if(type == TidyNode_Start || type == TidyNode_StartEnd)
    {
        ctmbstr name = tidyNodeGetName(tnod);
        if(name)
        {
            std::string n = name;
            if(n == "script" || n == "style" || n == "iframe" ||
               n == "object" || n == "applet" || n == "form")
            {
                TidyNode next = tidyGetNext(tnod);
                tidyDiscardElement(tdoc, tnod);
                sanitizeAST(tdoc, next); // Continue with next sibling
                return;
            }
        }

        // Discard dangerous attributes
        std::vector<TidyAttr> attrs_to_remove;
        for(TidyAttr attr = tidyAttrFirst(tnod); attr;
            attr = tidyAttrNext(attr))
        {
            ctmbstr attrName = tidyAttrName(attr);
            ctmbstr attrVal = tidyAttrValue(attr);
            if(attrName)
            {
                std::string an = attrName;
                if(an.find("on") == 0)
                { // onclick, onload, etc.
                    attrs_to_remove.push_back(attr);
                }
                else if(attrVal)
                {
                    std::string av = attrVal;
                    if(av.find("javascript:") == 0)
                    {
                        attrs_to_remove.push_back(attr);
                    }
                }
            }
        }
        for(TidyAttr attr : attrs_to_remove)
        {
            tidyAttrDiscard(tdoc, tnod, attr);
        }
    }

    for(TidyNode child = tidyGetChild(tnod); child; child = tidyGetNext(child))
    {
        sanitizeAST(tdoc, child);
    }
}

TidyNode findTargetLink(TidyNode tnod, const std::string& target_url)
{
    if(!tnod)
    {
        return nullptr;
    }
    TidyNodeType type = tidyNodeGetType(tnod);
    if(type == TidyNode_Start || type == TidyNode_StartEnd)
    {
        ctmbstr name = tidyNodeGetName(tnod);
        if(name && std::string(name) == "a")
        {
            for(TidyAttr attr = tidyAttrFirst(tnod); attr;
                attr = tidyAttrNext(attr))
            {
                ctmbstr attrName = tidyAttrName(attr);
                ctmbstr attrVal = tidyAttrValue(attr);
                if(attrName && std::string(attrName) == "href" && attrVal)
                {
                    if(std::string(attrVal) == target_url)
                    {
                        return tnod;
                    }
                }
            }
        }
    }
    for(TidyNode child = tidyGetChild(tnod); child; child = tidyGetNext(child))
    {
        TidyNode found = findTargetLink(child, target_url);
        if(found)
        {
            return found;
        }
    }
    return nullptr;
}

std::string serializeNode(TidyDoc tdoc, TidyNode tnod, size_t& current_length,
                          size_t max_length)
{
    if(!tnod || current_length >= max_length)
    {
        return "";
    }

    TidyNodeType type = tidyNodeGetType(tnod);
    if(type == TidyNode_Text)
    {
        TidyBuffer buf;
        tidyBufInit(&buf);
        tidyNodeGetValue(tdoc, tnod, &buf);
        std::string res;
        if(buf.bp)
        {
            res = htmlEscape((char*)buf.bp);
        }
        tidyBufFree(&buf);

        if(current_length + res.length() > max_length)
        {
            res = res.substr(0, max_length - current_length) + "...";
            current_length = max_length;
        }
        else
        {
            current_length += res.length();
        }
        return res;
    }
    else if(type == TidyNode_Start || type == TidyNode_End ||
            type == TidyNode_StartEnd)
    {
        std::string res;
        ctmbstr name = tidyNodeGetName(tnod);
        if(name)
        {
            res += "<" + std::string(name);
            for(TidyAttr attr = tidyAttrFirst(tnod); attr;
                attr = tidyAttrNext(attr))
            {
                ctmbstr attrName = tidyAttrName(attr);
                ctmbstr attrVal = tidyAttrValue(attr);
                if(attrName)
                {
                    res += " " + std::string(attrName);
                    if(attrVal)
                    {
                        res += "=\"" + htmlEscape(std::string(attrVal)) + "\"";
                    }
                }
            }
            if(type == TidyNode_StartEnd)
            {
                res += "/>";
            }
            else
            {
                res += ">";
            }
        }

        for(TidyNode child = tidyGetChild(tnod); child;
            child = tidyGetNext(child))
        {
            res += serializeNode(tdoc, child, current_length, max_length);
        }

        if(name && type != TidyNode_StartEnd)
        {
            res += "</" + std::string(name) + ">";
        }
        return res;
    }
    return "";
}

bool isBlockLevel(const std::string& name)
{
    static const std::set<std::string> blocks = {
        "p",  "div", "li", "blockquote", "article", "section", "h1",
        "h2", "h3",  "h4", "h5",         "h6",      "td",      "th"};
    return blocks.count(name) > 0;
}

std::optional<std::string> getAttr(TidyNode node, std::string_view name)
{
    for(TidyAttr a = tidyAttrFirst(node); a; a = tidyAttrNext(a))
    {
        ctmbstr n = tidyAttrName(a);
        if(n && std::string_view(n) == name)
        {
            ctmbstr v = tidyAttrValue(a);
            return v ? std::string(v) : std::string();
        }
    }
    return std::nullopt;
}

bool hasClassToken(TidyNode node, std::string_view token)
{
    auto cls = getAttr(node, "class");
    if(!cls.has_value())
    {
        return false;
    }
    const std::string& s = *cls;
    size_t i = 0;
    while(i < s.size())
    {
        while(i < s.size() &&
              std::isspace(static_cast<unsigned char>(s[i])))
        {
            ++i;
        }
        size_t j = i;
        while(j < s.size() &&
              !std::isspace(static_cast<unsigned char>(s[j])))
        {
            ++j;
        }
        if(j > i && std::string_view(s).substr(i, j - i) == token)
        {
            return true;
        }
        i = j;
    }
    return false;
}

TidyNode findFirstByClass(TidyNode node, std::string_view token)
{
    if(!node)
    {
        return nullptr;
    }
    TidyNodeType type = tidyNodeGetType(node);
    if((type == TidyNode_Start || type == TidyNode_StartEnd) &&
       hasClassToken(node, token))
    {
        return node;
    }
    for(TidyNode c = tidyGetChild(node); c; c = tidyGetNext(c))
    {
        if(TidyNode r = findFirstByClass(c, token))
        {
            return r;
        }
    }
    return nullptr;
}

void collectInnerText(TidyDoc tdoc, TidyNode node, std::string& out,
                      size_t max_len)
{
    if(!node || out.size() >= max_len)
    {
        return;
    }
    TidyNodeType type = tidyNodeGetType(node);
    if(type == TidyNode_Text)
    {
        TidyBuffer buf;
        tidyBufInit(&buf);
        tidyNodeGetValue(tdoc, node, &buf);
        if(buf.bp)
        {
            out += reinterpret_cast<const char*>(buf.bp);
        }
        tidyBufFree(&buf);
        return;
    }
    for(TidyNode c = tidyGetChild(node); c; c = tidyGetNext(c))
    {
        collectInnerText(tdoc, c, out, max_len);
        if(out.size() >= max_len)
        {
            return;
        }
    }
}

bool isUnsafeUrlScheme(const std::string& url)
{
    std::string lower;
    lower.reserve(11);
    for(size_t i = 0; i < url.size() && i < 11; ++i)
    {
        lower += static_cast<char>(
            std::tolower(static_cast<unsigned char>(url[i])));
    }
    return lower.starts_with("javascript:");
}

std::optional<std::string> photoFromNode(TidyNode node)
{
    ctmbstr name = tidyNodeGetName(node);
    if(!name)
    {
        return std::nullopt;
    }
    std::string n = name;
    std::optional<std::string> raw;
    if(n == "img")
    {
        raw = getAttr(node, "src");
    }
    else if(n == "a")
    {
        raw = getAttr(node, "href");
    }
    if(!raw.has_value() || raw->empty() || isUnsafeUrlScheme(*raw))
    {
        return std::nullopt;
    }
    return raw;
}

} // namespace

std::optional<std::string>
HtmlSanitizer::extractAndSanitizeSnippet(const std::string& raw_html,
                                         const std::string& target_url,
                                         size_t max_length)
{
    TidyDoc tdoc = tidyCreate();
    tidyOptSetBool(tdoc, TidyForceOutput, yes);
    tidyOptSetBool(tdoc, TidyBodyOnly, yes);
    tidyOptSetBool(tdoc, TidyMark, no);

    tidyParseString(tdoc, raw_html.c_str());
    tidyCleanAndRepair(tdoc);

    TidyNode body = tidyGetBody(tdoc);
    if(!body)
    {
        tidyRelease(tdoc);
        return std::nullopt;
    }

    sanitizeAST(tdoc, body);

    TidyNode linkNode = findTargetLink(body, target_url);
    if(!linkNode)
    {
        tidyRelease(tdoc);
        return std::nullopt;
    }

    TidyNode blockNode = linkNode;
    TidyNode parent = tidyGetParent(blockNode);
    while(parent)
    {
        ctmbstr name = tidyNodeGetName(parent);
        if(name)
        {
            std::string n = name;
            if(n == "body" || isBlockLevel(n))
            {
                if(n != "body" || blockNode == linkNode)
                {
                    if(n != "body")
                    {
                        blockNode = parent;
                    }
                }
                break;
            }
        }
        blockNode = parent;
        parent = tidyGetParent(blockNode);
    }

    size_t current_len = 0;
    std::string snippet =
        serializeNode(tdoc, blockNode, current_len, max_length);

    tidyRelease(tdoc);
    return snippet;
}

std::optional<std::string>
HtmlSanitizer::discoverWebmentionEndpoint(const std::string& raw_html)
{
    TidyDoc tdoc = tidyCreate();
    tidyOptSetBool(tdoc, TidyForceOutput, yes);
    tidyOptSetBool(tdoc, TidyMark, no);

    tidyParseString(tdoc, raw_html.c_str());
    tidyCleanAndRepair(tdoc);

    std::optional<std::string> endpoint;

    // We need to traverse in document order.
    auto find_endpoint = [&endpoint](auto& self, TidyNode tnod) -> void
    {
        if(!tnod || endpoint.has_value())
        {
            return;
        }

        TidyNodeType type = tidyNodeGetType(tnod);
        if(type == TidyNode_Start || type == TidyNode_StartEnd)
        {
            ctmbstr name = tidyNodeGetName(tnod);
            if(name)
            {
                std::string n = name;
                if(n == "link" || n == "a")
                {
                    std::string href;
                    bool has_webmention_rel = false;
                    bool has_href = false;
                    for(TidyAttr attr = tidyAttrFirst(tnod); attr;
                        attr = tidyAttrNext(attr))
                    {
                        ctmbstr attrName = tidyAttrName(attr);
                        ctmbstr attrVal = tidyAttrValue(attr);
                        if(attrName)
                        {
                            std::string an = attrName;
                            if(an == "href")
                            {
                                has_href = true;
                                if(attrVal)
                                {
                                    href = attrVal;
                                }
                            }
                            else if(an == "rel" && attrVal)
                            {
                                std::string av = attrVal;
                                // Split by space and check
                                size_t start = 0, end = 0;
                                while((end = av.find(' ', start)) !=
                                      std::string::npos)
                                {
                                    if(av.substr(start, end - start) ==
                                       "webmention")
                                    {
                                        has_webmention_rel = true;
                                    }
                                    start = end + 1;
                                }
                                if(av.substr(start) == "webmention")
                                {
                                    has_webmention_rel = true;
                                }
                            }
                        }
                    }
                    if(has_webmention_rel && has_href)
                    {
                        endpoint = href;
                        return;
                    }
                }
            }
        }

        for(TidyNode child = tidyGetChild(tnod); child;
            child = tidyGetNext(child))
        {
            self(self, child);
            if(endpoint.has_value())
            {
                return;
            }
        }
    };

    find_endpoint(find_endpoint, tidyGetRoot(tdoc));

    tidyRelease(tdoc);
    return endpoint;
}

HtmlSanitizer::AuthorInfo
HtmlSanitizer::extractAuthor(const std::string& raw_html)
{
    AuthorInfo info;

    TidyDoc tdoc = tidyCreate();
    tidyOptSetBool(tdoc, TidyForceOutput, yes);
    tidyOptSetBool(tdoc, TidyMark, no);
    tidyParseString(tdoc, raw_html.c_str());
    tidyCleanAndRepair(tdoc);

    TidyNode root = tidyGetRoot(tdoc);
    TidyNode author_root = findFirstByClass(root, "p-author");

    // Photo. If we have a p-author subtree, look there first; the
    // p-author element itself may carry u-photo (e.g. <a class=
    // "p-author u-photo">). Otherwise fall back to a document-wide
    // u-photo.
    TidyNode photo_node = nullptr;
    if(author_root)
    {
        if(hasClassToken(author_root, "u-photo"))
        {
            photo_node = author_root;
        }
        else
        {
            photo_node = findFirstByClass(author_root, "u-photo");
        }
    }
    if(!photo_node)
    {
        photo_node = findFirstByClass(root, "u-photo");
    }
    if(photo_node)
    {
        if(auto src = photoFromNode(photo_node); src.has_value())
        {
            std::string_view stripped = mw::strip(*src);
            if(!stripped.empty())
            {
                info.photo = std::string(stripped);
            }
        }
    }

    // Name. Prefer p-name within the p-author subtree; otherwise use
    // the inner text of p-author itself; otherwise fall back to a
    // document-wide p-name.
    constexpr size_t MAX_NAME_LEN = 200;
    auto extract_text = [&](TidyNode n) -> std::optional<std::string>
    {
        std::string text;
        collectInnerText(tdoc, n, text, MAX_NAME_LEN);
        std::string_view stripped = mw::strip(text);
        if(stripped.empty())
        {
            return std::nullopt;
        }
        return std::string(stripped);
    };

    if(author_root)
    {
        if(TidyNode name_node = findFirstByClass(author_root, "p-name");
           name_node)
        {
            info.name = extract_text(name_node);
        }
        else
        {
            info.name = extract_text(author_root);
            // <img class="p-author"> has no inner text; fall back to alt.
            if(!info.name.has_value())
            {
                ctmbstr tag = tidyNodeGetName(author_root);
                if(tag && std::string(tag) == "img")
                {
                    if(auto alt = getAttr(author_root, "alt");
                       alt.has_value())
                    {
                        std::string_view stripped = mw::strip(*alt);
                        if(!stripped.empty())
                        {
                            info.name = std::string(stripped);
                        }
                    }
                }
            }
        }
    }
    else
    {
        if(TidyNode name_node = findFirstByClass(root, "p-name"); name_node)
        {
            info.name = extract_text(name_node);
        }
    }

    tidyRelease(tdoc);
    return info;
}
