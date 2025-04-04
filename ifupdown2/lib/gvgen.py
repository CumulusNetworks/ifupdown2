#!/usr/bin/python
# -*- coding: utf-8 -*-
# $Id$
"""
GvGen - Generate dot file to be processed by graphviz
The MIT License (MIT)
Copyright (c) 2007-2020 Sebastien Tricaud <sebastien at honeynet org>
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from six import iteritems
from sys import stdout

gvgen_version = "1.0"

debug = 0
debug_tree_unroll = 0


class GvGen:
    """
    Graphviz dot language Generation Class
    For example of usage, please see the __main__ function
    """

    def __init__(self, legend_name=None, options="compound=true;"):  # allow links between clusters
        self.max_line_width = 10
        self.max_arrow_width = 2
        self.line_factor = 1
        self.arrow_factor = 0.5
        self.initial_line_width = 1.2
        self.initial_arrow_width = 0.8

        self.options = {}
        for option in options.split(";"):
            option = option.strip()
            if not option:
                continue
            key, value = option.split("=", 1)
            self.setOptions(**{key: value})

        self.__id = 0
        self.__nodes = []
        self.__links = []
        self.__browse_level = 0  # Stupid depth level for self.browse
        self.__opened_braces = []  # We count opened clusters
        self.fd = stdout  # File descriptor to output dot
        self.padding_str = "   "  # Left padding to make children and parent look nice
        self.__styles = {}
        self.__default_style = []
        self.smart_mode = 0  # Disabled by default

        # The graph has a legend
        if legend_name:
            self.legend = self.newItem(legend_name)

    def setOptions(self, **options):
        for key, value in iteritems(options):
            self.options[key] = value

    def __node_new(self, name, parent=None, distinct=None):
        """
        Create a new node in the data structure
        @name: Name of the node, that will be the graphviz label
        @parent: The node parent
        @distinct: if true, will not create and node that has the same name
        Returns: The node created
        """

        # We first check for distincts
        if distinct:
            if self.__nodes:
                for e in self.__nodes:
                    props = e['properties']
                    if props['label'] == name:
                        # We found the label name matching, we return -1
                        return -1

        # We now insert into gvgen datastructure
        self.__id += 1
        node = {'id': self.__id,  # Internal ID
                'lock': 0,  # When the node is written, it is locked to avoid further references
                'parent': parent,  # Node parent for easy graphviz clusters
                'style': None,  # Style that GvGen allow you to create
                'properties': {  # Custom graphviz properties you can add, which will overide previously defined styles
                    'label': name
                }
                }

        # Parents should be sorted first
        if parent:
            self.__nodes.insert(1, self.__nodes.pop(self.__nodes.index(parent)))

        self.__nodes.append(node)
        return node

    def __link_smart(self, link):
        """
        Creates a smart link if smart_mode activated:
          if a -> b exists, and we now add a <- b,
          instead of doing:  a -> b
                               <-
          we do: a <-> b
        """

        linkfrom = self.__link_exists(link['from_node'], link['to_node'])
        linkto = self.__link_exists(link['to_node'], link['from_node'])

        if self.smart_mode:
            if linkto:
                self.__links.remove(linkto)
                self.propertyAppend(link, "dir", "both")

            pw = self.propertyGet(linkfrom, "penwidth")
            if pw:
                pw = float(pw)
                pw += self.line_factor
                if pw < self.max_line_width:
                    self.propertyAppend(linkfrom, "penwidth", str(pw))
            else:
                self.propertyAppend(link, "penwidth", str(self.initial_line_width))

            aw = self.propertyGet(linkfrom, "arrowsize")
            if aw:
                aw = float(aw)
                if aw < self.max_arrow_width:
                    aw += self.arrow_factor
                    self.propertyAppend(linkfrom, "arrowsize", str(aw))
            else:
                self.propertyAppend(link, "arrowsize", str(self.initial_arrow_width))

        if not linkfrom:
            self.__links.append(link)

    def __link_new(self, from_node, to_node, label=None, cl_from_node=None, cl_to_node=None):
        """
        Creates a link between two nodes
        @from_node: The node the link comes from
        @to_node: The node the link goes to
        Returns: The link created
        """

        link = {'from_node': from_node,
                'to_node': to_node,
                'style': None,  # Style that GvGen allow you to create
                'properties': {},
                # Custom graphviz properties you can add, which will overide previously defined styles
                'cl_from_node': None,  # When linking from a cluster, the link appears from this node
                'cl_to_node': None,  # When linking to a cluster, the link appears to go to this node
                }

        if label:
            link['properties']['label'] = label

        if cl_from_node:
            link['cl_from_node'] = cl_from_node
        if cl_to_node:
            link['cl_to_node'] = cl_to_node

        # We let smart link work for us
        self.__link_smart(link)

        return link

    def __link_exists(self, from_node, to_node):
        """
        Find if a link exists
        @from_node: The node the link comes from
        @to_node: The node the link goes to
        Returns: true if the given link already exists
        """

        for link in self.__links:
            if link['from_node'] == from_node and link['to_node'] == to_node:
                return link

        return None

    def __has_children(self, parent):
        """
        Find children to a given parent
        Returns the children list
        """
        children_list = []
        for e in self.__nodes:
            if e['parent'] == parent:
                children_list.append(e)

        return children_list

    def newItem(self, name, parent=None, distinct=None):
        node = self.__node_new(name, parent, distinct)

        return node

    def newLink(self, src, dst, label=None, cl_src=None, cl_dst=None):
        """
        Link two existing nodes with each other
        """

        return self.__link_new(src, dst, label, cl_src, cl_dst)

    def debug(self):
        for e in self.__nodes:
            print("element = {0}".format(e['id']))

    def collectLeaves(self, parent):
        """
        Collect every leaf sharing the same parent
        """
        cl = []
        for e in self.__nodes:
            if e['parent'] == parent:
                cl.append(e)

        return cl

    def collectUnlockedLeaves(self, parent):
        """
        Collect every leaf sharing the same parent
        unless it is locked
        """
        cl = []
        for e in self.__nodes:
            if e['parent'] == parent and not e['lock']:
                cl.append(e)
        return cl

    def lockNode(self, node):
        node['lock'] = 1

    #
    # Start: styles management
    #
    def styleAppend(self, stylename, key, val):
        if stylename not in self.__styles:
            self.__styles[stylename] = []

        self.__styles[stylename].append([key, val])

    def styleApply(self, stylename, node_or_link):
        node_or_link['style'] = stylename

    def styleDefaultAppend(self, key, val):
        self.__default_style.append([key, val])

    #
    # End: styles management
    #

    #
    # Start: properties management
    #
    def propertiesAsStringGet(self, node, props):
        """
        Get the properties string according to parent/children
        props is the properties dictionary
        """

        allProps = {}

        #
        # Default style come first, they can then be overriden
        #
        if self.__default_style:
            allProps.update(self.__default_style)

        #
        # First, we build the styles
        #
        if node['style']:
            stylename = node['style']
            allProps.update(self.__styles[stylename])

        #
        # Now we build the properties:
        # remember they override styles
        #
        allProps.update(props)

        if self.__has_children(node):
            propStringList = ["%s=\"%s\";\n" % (k, v) for k, v in iteritems(allProps)]
            properties = ''.join(propStringList)
        else:
            if props:
                propStringList = ["%s=\"%s\"" % (k, v) for k, v in iteritems(allProps)]
                properties = '[' + ','.join(propStringList) + ']'
            else:
                properties = ''

        return properties

    def propertiesLinkAsStringGet(self, link):
        props = {}

        if link['style']:
            stylename = link['style']

            # Build the properties string for node
            props.update(self.__styles[stylename])

        props.update(link['properties'])

        properties = ''
        if props:
            properties += ','.join(["%s=\"%s\"" % (str(k), str(val)) for k, val in iteritems(props)])
        return properties

    def propertyForeachLinksAppend(self, node, key, val):
        for l in self.__links:
            if l['from_node'] == node:
                props = l['properties']
                props[key] = val

    def propertyAppend(self, node_or_link, key, val):
        """
        Append a property to the wanted node or link
        mynode = newItem(\"blah\")
        Ex. propertyAppend(mynode, \"color\", \"red\")
        """
        props = node_or_link['properties']
        props[key] = val

    def propertyGet(self, node_or_link, key):
        """
        Get the value of a given property
        Ex. prop = propertyGet(node, \"color\")
        """
        try:
            props = node_or_link['properties']
            return props[key]
        except Exception:
            return None

    def propertyRemove(self, node_or_link, key):
        """
        Remove a property to the wanted node or link
        mynode = newItem(\"blah\")
        Ex. propertyRemove(mynode, \"color\")
        """
        props = node_or_link['properties']
        del props[key]

    #
    # End: Properties management
    #

    #
    # For a good legend, it has to be top to bottom whatever the rankdir
    #

    def legendAppend(self, legendstyle, legenddescr, labelin=None):

        # Determining if we need links according to rankdir
        needLinks = True

        if "rankdir" not in self.options:
            needLinks = False
        else:
            if self.options['rankdir'] == "LR":
                needLinks = False
            elif self.options['rankdir'] == "RL":
                needLinks = False
            elif self.options['rankdir'] == "TB":
                needLinks = True
            elif self.options['rankdir'] == "BT":
                needLinks = True

        # if the label is in the shape
        if labelin:

            # creating shape with label
            item = self.newItem(legenddescr, self.legend)
            self.styleApply(legendstyle, item)

            # if links needed
            if needLinks:

                # we link all the nodes if they are here
                if self.__has_children(self.legend):

                    # remember the previous one
                    previousNode = None
                    for node in self.__has_children(self.legend):
                        # and if they are more than two
                        if previousNode:
                            link = self.newLink(previousNode, node)
                            self.propertyAppend(link, "dir", "none")
                            self.propertyAppend(link, "style", "invis")

                        # remembering node for next iteration
                        previousNode = node

        else:
            # creating shapes and labels separately
            style = self.newItem("", self.legend)
            descr = self.newItem(legenddescr, self.legend)
            self.styleApply(legendstyle, style)
            link = self.newLink(style, descr)

            # linking labels and shapes
            self.propertyAppend(link, "dir", "none")
            self.propertyAppend(link, "style", "invis")
            self.propertyAppend(descr, "shape", "plaintext")

            # if links needed
            if needLinks:
                # removing constraints
                self.propertyAppend(link, "constraint", "false")

                # we link all the nodes if they are here
                if self.__has_children(self.legend):

                    # remember the previous one
                    previousNode = None
                    previousLabel = None

                    for node in self.__has_children(self.legend):
                        # if it has no text, meaning its a shape
                        if node['properties']['label'] == "":
                            # and if they are more than two
                            if previousNode:
                                link = self.newLink(previousNode, node)
                                self.propertyAppend(link, "dir", "none")
                                self.propertyAppend(link, "style", "invis")

                            # remembering ...
                            previousNode = node

                        else:
                            # else its labels
                            if previousLabel:
                                link = self.newLink(previousLabel, node)
                                self.propertyAppend(link, "dir", "none")
                                self.propertyAppend(link, "style", "invis")

                            # remembering previous label for next iteration
                            previousLabel = node

    def tree_debug(self, level, node, children):
        if children:
            print("(level:{0}) Eid:{1} has children ({2})").format(
                level, node['id'], str(children)
            )
        else:
            print("Eid: {0} has no children".format(str(node['id'])))

    #
    # Core function that outputs the data structure tree into dot language
    #
    def tree(self, level, node, children):
        """
        Core function to output dot which sorts out parents and children
        and do it in the right order
        """
        if debug:
            print("/* Grabed node = {0}*/".format(str(node['id'])))

        if node['lock'] == 1:  # The node is locked, nothing should be printed
            if debug:
                print("/* The node ({0}) is locked */".format(str(node['id'])))

            if self.__opened_braces:
                self.fd.write(level * self.padding_str)
                self.fd.write("}\n")
                self.__opened_braces.pop()
            return

        props = node['properties']

        if children:
            node['lock'] = 1
            self.fd.write(level * self.padding_str)
            self.fd.write(self.padding_str + "subgraph cluster%d {\n" % node['id'])
            properties = self.propertiesAsStringGet(node, props)
            self.fd.write(level * self.padding_str)
            self.fd.write(self.padding_str + "%s" % properties)
            self.__opened_braces.append([node, level])
        else:
            # We grab appropriate properties
            properties = self.propertiesAsStringGet(node, props)

            # We get the latest opened elements
            if self.__opened_braces:
                last_cluster, last_level = self.__opened_braces[-1]
            else:
                last_cluster = None
                last_level = 0

            if debug:
                if node['parent']:
                    parent_str = str(node['parent']['id'])
                else:
                    parent_str = 'None'
                if last_cluster:
                    last_cluster_str = str(last_cluster['id'])
                else:
                    last_cluster_str = 'None'
                print("/* e[parent] = {0}, last_cluster = {1}, last_level = {2}, opened_braces: {3} */".format(  # NOQA
                    parent_str, last_cluster_str, last_level, str(self.__opened_braces)
                ))

            # Write children/parent with properties
            if node['parent']:
                if node['parent'] != last_cluster:
                    while last_cluster and node['parent'] < last_cluster:
                        last_cluster, last_level = self.__opened_braces[-1]
                        if node['parent'] == last_cluster:
                            last_level += 1
                            # We browse any property to build a string
                            self.fd.write(last_level * self.padding_str)
                            self.fd.write(self.padding_str + "node%d %s;\n" % (node['id'], properties))
                            node['lock'] = 1
                        else:
                            self.fd.write(last_level * self.padding_str)
                            self.fd.write(self.padding_str + "}\n")
                            self.__opened_braces.pop()
                else:
                    self.fd.write(level * self.padding_str)
                    self.fd.write(self.padding_str + "node%d %s;\n" % (node['id'], properties))
                    node['lock'] = 1
                    cl = self.collectUnlockedLeaves(node['parent'])
                    for l in cl:
                        props = l['properties']
                        properties = self.propertiesAsStringGet(l, props)
                        self.fd.write(last_level * self.padding_str)
                        self.fd.write(self.padding_str + self.padding_str + "node%d %s;\n" % (l['id'], properties))
                        node['lock'] = 1
                        self.lockNode(l)

                    self.fd.write(level * self.padding_str + "}\n")
                    self.__opened_braces.pop()

            else:
                self.fd.write(self.padding_str + "node%d %s;\n" % (node['id'], properties))
                node['lock'] = 1

    def browse(self, node, cb):
        """
        Browse nodes in a tree and calls cb providing node parameters
        """
        children = self.__has_children(node)
        if children:
            cb(self.__browse_level, node, str(children))
            for c in children:
                self.__browse_level += 1
                self.browse(c, cb)

        else:
            cb(self.__browse_level, node, None)
            self.__browse_level = 0

    #            if debug:
    #                print "This node is not a child: " + str(node)

    def dotLinks(self, node):
        """
        Write links between nodes
        """
        for l in self.__links:
            if l['from_node'] == node:
                # Check if we link form a cluster
                children = self.__has_children(node)
                if children:
                    if l['cl_from_node']:
                        src = l['cl_from_node']['id']
                    else:
                        src = children[0]['id']
                    cluster_src = node['id']
                else:
                    src = node['id']
                    cluster_src = ''

                # Check if we link to a cluster
                children = self.__has_children(l['to_node'])
                if children:
                    if l['cl_to_node']:
                        dst = l['cl_to_node']['id']
                    else:
                        dst = children[0]['id']
                    cluster_dst = l['to_node']['id']
                else:
                    dst = l['to_node']['id']
                    cluster_dst = ''

                self.fd.write("node%d->node%d" % (src, dst))

                props = self.propertiesLinkAsStringGet(l)

                # Build new properties if we link from or to a cluster
                if cluster_src:
                    if props:
                        props += ','
                    props += "ltail=cluster%d" % cluster_src
                if cluster_dst:
                    if props:
                        props += ','
                    props += "lhead=cluster%d" % cluster_dst

                if props:
                    self.fd.write(" [%s]" % props)

                self.fd.write(";\n")

    def dot(self, fd=stdout):
        """
        Translates the datastructure into dot
        """
        try:
            self.fd = fd

            self.fd.write("/* Generated by GvGen v.%s (https://www.github.com/stricaud/gvgen) */\n\n" % (gvgen_version))

            self.fd.write("digraph G {\n")

            if self.options:
                for key, value in iteritems(self.options):
                    self.fd.write("%s=%s;" % (key, value))
                self.fd.write("\n")

            # We write parents and children in order
            for e in self.__nodes:
                if debug_tree_unroll:
                    self.browse(e, self.tree_debug)
                else:
                    self.browse(e, self.tree)

            # We write the connection between nodes
            for e in self.__nodes:
                self.dotLinks(e)

            # We put all the nodes belonging to the parent
            self.fd.write("}\n")
        finally:
            # Remove our reference to file descriptor
            self.fd = None
