# Burp extension to test adding a tab.
# somewhat based on https://laconicwolf.com/2019/02/07/burp-extension-python-tutorial-encode-decode-hash/

# support for burp-exceptions - see https://github.com/securityMB/burp-exceptions
try:
    from exceptions_fix import FixBurpExceptions
    import sys
except ImportError:
    pass

# support for burputils - https://github.com/parsiya/burputils
# comment if not using burputils
from burputils import BurpUtils
from burp import IBurpExtender

# needed for tab
from burp import ITab

class BurpExtender(IBurpExtender, ITab):
    # implement IBurpExtender

    # set everything up
    def registerExtenderCallbacks(self, callbacks):
        # create BurpUtils
        self.utils = BurpUtils(callbacks.getHelpers())

        # support for burp-exceptions
        try:
            sys.stdout = callbacks.getStdout()
        except:
            pass
        
        # set our extension name
        callbacks.setExtensionName("Test ITab")
        
        # add the tab to Burp's UI
        callbacks.addSuiteTab(self)

    #
    # implement ITab
    # https://portswigger.net/burp/extender/api/burp/ITab.html
    # two methods must be implemented.

    def getTabCaption(self):
        """Burp uses this method to obtain the caption that should appear on the
        custom tab when it is displayed. Returns a string with the tab name.
        """
        return "Example Tab"
    
    def getUiComponent(self):
        """Burp uses this method to obtain the component that should be used as
        the contents of the custom tab when it is displayed.
        Returns a awt.Component.
        """
        from javax.swing import JPanel, JSplitPane, JScrollPane
        from java.awt import BorderLayout
        # skipping a couple of steps compared to Laconic Wolf's tutorial.
        # this will add an empty tab named "Example Tab" to Burp.
        # return JPanel(BorderLayout())

        # from here, it's a Java Swing GUI problem.
        # can I use NetBeans to create an IDE

        # using these tutorials
        # https://docs.oracle.com/javase/tutorial/uiswing/components/panel.html
        # https://docs.oracle.com/javase/tutorial/uiswing/layout/using.html
        # https://wiki.python.org/jython/SwingExamples

        # customizing the tab
        panel = JPanel(BorderLayout())

        # under "Adding Components" - We are using BorderLayout so we need to
        # specify the components' position when using add.
        # How to use the BorderLayout:
        # https://docs.oracle.com/javase/tutorial/uiswing/layout/border.html
        # PAGE_START - PAGE_END - LINE_START - LINE_END - CENTER

        # create and add a bunch of buttons to test the positions 
        # button1 = JButton("PAGE_START")
        # panel.add(button1, BorderLayout.PAGE_START)

        # this will take most of the tab.
        # button2 = JButton("CENTER")
        # panel.add(button2, BorderLayout.CENTER)

        # button3 = JButton("PAGE_END")
        # panel.add(button3, BorderLayout.PAGE_END)

        # this is a really great UI that I want to implement.
        # http://burpextensions.blogspot.com/2012/08/adding-gui-features-to-extension.html

        # create a split pane (left and right ones)
        # https://wiki.python.org/jython/SwingExamples#JSplitPane
        # https://docs.oracle.com/javase/tutorial/uiswing/components/splitpane.html
        # use JSplitPane.VERTICAL_SPLIT for top and bottom panes.
        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        # there is a version of the method with int parameter which splits
        # by absolute unites. E.g., split.setDividerLocation(150)
        
        # the one with a double parameter, uses percentages.
        # this means 20% will go to left and the rest goes to right.
        # see more https://docs.oracle.com/javase/7/docs/api/javax/swing/JSplitPane.html
        split.setDividerLocation(0.2)

        # assign the left tab
        # JScrollPane: https://docs.oracle.com/javase/7/docs/api/javax/swing/JScrollPane.html
        # Jython example: https://gist.github.com/jjam3774/6162523
        scroll = JScrollPane(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED)

        # inside the scroll we want to display a JList
        # 
        # https://docs.oracle.com/javase/7/docs/api/javax/swing/JList.html
        scroll.viewport.view = 

        split.
        
        
        panel.add(split)



        return panel

# support for burp-exceptions
try:
    FixBurpExceptions()
except:
    pass