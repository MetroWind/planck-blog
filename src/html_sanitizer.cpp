#include "html_sanitizer.hpp"

#include <algorithm>
#include <cstring>

#include <tidy.h>
#include <tidybuffio.h>

namespace
{

bool isDangerousTag(const char* tag)
{
    if(!tag)
    {
        return false;
    }
    std::string t = tag;
    std::transform(t.begin(), t.end(), t.begin(), ::tolower);
    return t == "script" || t == "style" || t == "iframe" || t == "object" ||
           t == "embed" || t == "applet" || t == "form" || t == "link" ||
           t == "meta" || t == "base";
}

bool isBlockLevel(const char* tag)
{
    if(!tag)
    {
        return false;
    }
    std::string t = tag;
    std::transform(t.begin(), t.end(), t.begin(), ::tolower);
    return t == "p" || t == "div" || t == "blockquote" || t == "li" ||
           t == "section" || t == "article" || t == "header" || t == "footer" ||
           t == "ul" || t == "ol" || t == "body" || t == "html";
}

void serializeNode(TidyDoc tdoc, TidyNode tnod, std::string& out,
                   size_t max_length)
{
    if(out.length() >= max_length)
    {
        return;
    }

    TidyNodeType type = tidyNodeGetType(tnod);
    ctmbstr name = tidyNodeGetName(tnod);

    if(type == TidyNode_Text)
    {
        TidyBuffer buf;
        tidyBufInit(&buf);
        tidyNodeGetText(tdoc, tnod, &buf);
        if(buf.bp)
        {
            std::string text = reinterpret_cast<const char*>(buf.bp);
            if(out.length() + text.length() > max_length)
            {
                out += text.substr(0, max_length - out.length());
                out += "...";
            }
            else
            {
                out += text;
            }
        }
        tidyBufFree(&buf);
        return;
    }

    if(name && isDangerousTag(name))
    {
        return;
    }

    bool is_tag = (type == TidyNode_Start || type == TidyNode_StartEnd);
    if(is_tag && name)
    {
        out += "<";
        out += name;
        TidyAttr attr = tidyAttrFirst(tnod);
        while(attr)
        {
            ctmbstr attr_name = tidyAttrName(attr);
            ctmbstr attr_value = tidyAttrValue(attr);
            if(attr_name)
            {
                std::string aname = attr_name;
                std::transform(aname.begin(), aname.end(), aname.begin(),
                               ::tolower);
                if(aname.find("on") != 0 && aname != "style")
                {
                    if(aname == "href" || aname == "src")
                    {
                        if(attr_value)
                        {
                            std::string val = attr_value;
                            std::transform(val.begin(), val.end(), val.begin(),
                                           ::tolower);
                            if(val.find("javascript:") == 0 ||
                               val.find("data:") == 0 ||
                               val.find("vbscript:") == 0)
                            {
                                // skip dangerous URL
                            }
                            else
                            {
                                out += " ";
                                out += aname;
                                out += "=\"";
                                out += attr_value;
                                out += "\"";
                            }
                        }
                    }
                    else
                    {
                        out += " ";
                        out += aname;
                        if(attr_value)
                        {
                            out += "=\"";
                            out += attr_value;
                            out += "\"";
                        }
                    }
                }
            }
            attr = tidyAttrNext(attr);
        }
        out += ">";
    }

    TidyNode child = tidyGetChild(tnod);
    while(child)
    {
        serializeNode(tdoc, child, out, max_length);
        child = tidyGetNext(child);
    }

    if(type == TidyNode_Start && name)
    {
        out += "</";
        out += name;
        out += ">";
    }
}

TidyNode findTargetLink(TidyDoc tdoc, TidyNode tnod, const std::string& target)
{
    TidyNodeType type = tidyNodeGetType(tnod);
    ctmbstr name = tidyNodeGetName(tnod);

    if(type == TidyNode_Start && name)
    {
        std::string t = name;
        std::transform(t.begin(), t.end(), t.begin(), ::tolower);
        if(t == "a")
        {
            TidyAttr attr = tidyAttrFirst(tnod);
            while(attr)
            {
                ctmbstr attr_name = tidyAttrName(attr);
                ctmbstr attr_value = tidyAttrValue(attr);
                if(attr_name && attr_value)
                {
                    std::string aname = attr_name;
                    std::transform(aname.begin(), aname.end(), aname.begin(),
                                   ::tolower);
                    if(aname == "href" && std::string(attr_value) == target)
                    {
                        return tnod;
                    }
                }
                attr = tidyAttrNext(attr);
            }
        }
    }

    TidyNode child = tidyGetChild(tnod);
    while(child)
    {
        TidyNode found = findTargetLink(tdoc, child, target);
        if(found)
        {
            return found;
        }
        child = tidyGetNext(child);
    }
    return nullptr;
}
} // namespace

std::optional<std::string>
HtmlSanitizer::extractAndSanitizeSnippet(const std::string& raw_html,
                                         const std::string& target_url,
                                         size_t max_length)
{
    TidyDoc tdoc = tidyCreate();
    if(!tdoc)
    {
        return std::nullopt;
    }

    tidyOptSetBool(tdoc, TidyForceOutput, yes);
    tidyOptSetBool(tdoc, TidyBodyOnly, yes);
    tidyOptSetBool(tdoc, TidyMark, no);

    int rc = tidyParseString(tdoc, raw_html.c_str());
    if(rc >= 0)
    {
        tidyCleanAndRepair(tdoc);
    }

    TidyNode root = tidyGetBody(tdoc);
    if(!root)
    {
        root = tidyGetHtml(tdoc);
    }
    if(!root)
    {
        root = tidyGetRoot(tdoc);
    }

    TidyNode targetNode = findTargetLink(tdoc, root, target_url);

    if(!targetNode)
    {
        tidyRelease(tdoc);
        return std::nullopt;
    }

    TidyNode blockNode = targetNode;
    while(blockNode)
    {
        ctmbstr name = tidyNodeGetName(blockNode);
        if(isBlockLevel(name))
        {
            break;
        }
        TidyNode parent = tidyGetParent(blockNode);
        if(!parent)
        {
            break;
        }
        blockNode = parent;
    }
    if(!blockNode)
    {
        blockNode = targetNode;
    }

    std::string snippet;
    serializeNode(tdoc, blockNode, snippet, max_length);

    tidyRelease(tdoc);
    return snippet;
}
