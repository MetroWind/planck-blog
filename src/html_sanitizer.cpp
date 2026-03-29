#include "html_sanitizer.hpp"

#include <algorithm>
#include <set>
#include <vector>

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
