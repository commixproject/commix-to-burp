/*
 * This file is part of the commix-to-burp extension (https://github.com/commixproject/commix-to-burp).
 * Copyright 2026 Anastasios Stasinopoulos (@ancst).
 *
 * Licensed under the Apache License, Version 2.0; see the LICENSE file for details.
 */

package com.commixproject.burp;

import burp.api.montoya.persistence.PersistedObject;

import javax.swing.*;
import javax.swing.border.MatteBorder;
import java.awt.*;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Everything worth setting before a scan starts, the way it would be typed on the command line -
 * a dropdown or a checkbox wherever commix only takes one of a fixed set of values, a text field
 * everywhere else. Shown once per scan, pre-filled with whatever was chosen last time. Detection
 * (tamper scripts and manual detection markers folded in) is the only tab shown by default; a
 * "Show advanced options" checkbox reveals Injection, Session & request and Post-exploitation for
 * everything past a first scan. A couple of controls disable each other outright instead of just
 * complaining after the fact, for combinations commix itself refuses to run.
 */
public final class ScanOptionsDialog {

    private static final Color MUTED = new Color(0x75, 0x75, 0x75);
    private static final String[] EVAL_LANGUAGES = {"(none)", "php", "python", "ruby", "javascript", "powershell"};
    private static final String[] OS_CHOICES = {"(auto-detect)", "unix", "windows"};
    private static final String[] AUTH_TYPES = {"(none)", "basic", "digest", "bearer"};

    private final PersistedObject store;

    // Detection
    private final JComboBox<Integer> level = new JComboBox<>(new Integer[]{1, 2, 3});
    private final JCheckBox techResults = new JCheckBox("Results-based");
    private final JCheckBox techBoolean = new JCheckBox("Boolean-based");
    private final JCheckBox techTime = new JCheckBox("Time-based");
    private final JCheckBox techFile = new JCheckBox("File-based");
    private final JCheckBox oob = new JCheckBox("Out-of-band (--oob)");
    private final JCheckBox skipWaf = new JCheckBox("Skip WAF/IPS detection");
    private final JCheckBox skipHeuristics = new JCheckBox("Skip heuristic checks");
    private final JCheckBox proof = new JCheckBox("Prove exploitation (--proof)");
    private final JCheckBox textOnly = new JCheckBox("Compare pages by text only (--text-only)");
    private final JCheckBox smart = new JCheckBox("Thorough tests only on positive heuristics (--smart)");
    private final JCheckBox skipStatic = new JCheckBox("Skip parameters that look static (--skip-static)");
    private final JCheckBox skipEmpty = new JCheckBox("Skip empty-valued parameters (--skip-empty)");
    private final JTextField webRoot = new JTextField();
    private final JTextField tmpPath = new JTextField();
    private final JTextField stringField = new JTextField();
    private final JTextField notStringField = new JTextField();
    private final JTextField regexpField = new JTextField();
    private final JTextField codeField = new JTextField();

    // Tamper
    private final JTextField tamperField = new JTextField();

    // Injection
    private final JComboBox<String> evalLanguage = new JComboBox<>(EVAL_LANGUAGES);
    private final JTextField testParameter = new JTextField();
    private final JTextField skipParameter = new JTextField();
    private final JTextField prefix = new JTextField();
    private final JTextField suffix = new JTextField();
    private final JComboBox<String> forceOs = new JComboBox<>(OS_CHOICES);
    private final JTextField maxLen = new JTextField();

    // Session & request
    private final JCheckBox flushSession = new JCheckBox("Flush session (--flush-session)");
    private final JCheckBox randomAgent = new JCheckBox("Random User-Agent");
    private final JCheckBox mobile = new JCheckBox("Mobile User-Agent (--mobile)");
    private final JCheckBox tor = new JCheckBox("Use Tor");
    private final JCheckBox unstable = new JCheckBox("Unstable connection (--unstable)");
    private final JTextField proxy = new JTextField();
    private final JComboBox<String> authType = new JComboBox<>(AUTH_TYPES);
    private final JTextField authCred = new JTextField();
    private final JTextField ignoreCode = new JTextField();
    private final JTextField abortCode = new JTextField();
    private final JTextField delay = new JTextField();
    private final JTextField timeout = new JTextField();
    private final JTextField retries = new JTextField();
    private final JTextField timeSec = new JTextField();
    private final JTextField timeLimit = new JTextField();
    private final JTextField jitter = new JTextField();
    private final JCheckBox ignoreRedirects = new JCheckBox("Ignore redirects (--ignore-redirects)");
    private final JCheckBox ignoreTimeouts = new JCheckBox("Ignore connection timeouts (--ignore-timeouts)");
    private final JCheckBox dropSetCookie = new JCheckBox("Ignore Set-Cookie headers (--drop-set-cookie)");
    private final JSpinner threads = new JSpinner(new SpinnerNumberModel(1, 1, 10, 1));
    private final JComboBox<Integer> verbosity = new JComboBox<>(new Integer[]{0, 1, 2, 3, 4});

    // Post-exploitation: commands
    private final JTextField osCmd = new JTextField();

    // Post-exploitation: file access
    private final JTextField fileRead = new JTextField();
    private final JTextField fileWrite = new JTextField();
    private final JTextField fileDest = new JTextField();
    private final JCheckBox commonFiles = new JCheckBox("Check for common files (--common-files)");

    // Post-exploitation: enumeration
    private final JCheckBox enumAll = new JCheckBox("Everything (--all)");
    private final JCheckBox enumCurrentUser = new JCheckBox("Current user");
    private final JCheckBox enumHostname = new JCheckBox("Hostname");
    private final JCheckBox enumIsRoot = new JCheckBox("Is root");
    private final JCheckBox enumIsAdmin = new JCheckBox("Is admin");
    private final JCheckBox enumSysInfo = new JCheckBox("System info");
    private final JCheckBox enumPrivileges = new JCheckBox("Privileges");
    private final JCheckBox enumUsers = new JCheckBox("Users");
    private final JCheckBox enumPasswords = new JCheckBox("Passwords");
    private final JCheckBox enumPsVersion = new JCheckBox("PowerShell version");

    private final JCheckBox advancedToggle = new JCheckBox("Show advanced options");
    private final JTabbedPane tabs = new JTabbedPane();

    private boolean started = false;

    private ScanOptionsDialog(CommixSettings settings) {
        this.store = settings.store();

        // commix rejects these combinations outright; disabling the loser as soon as its rival is
        // picked (rather than only complaining after Start Scan) keeps the dialog from ever being
        // able to submit them in the first place.
        oob.addItemListener(e -> refreshConflicts());
        randomAgent.addItemListener(e -> refreshConflicts());
        mobile.addItemListener(e -> refreshConflicts());
        advancedToggle.addItemListener(e -> refreshAdvancedTabs());
    }

    /**
     * Shows the dialog modally; empty if the user cancelled, otherwise the options to send.
     * 'markedParameters' - names of request parameters wrapped in Burp's own '§...§' markers -
     * pre-fill the test-parameter field for this scan, overriding whatever was remembered from
     * last time (the user marked them just now, which beats a stale default).
     */
    public static Optional<Map<String, Object>> show(Window parent, CommixSettings settings,
                                                       List<String> markedParameters) {
        ScanOptionsDialog instance = new ScanOptionsDialog(settings);
        instance.load();
        if (markedParameters != null && !markedParameters.isEmpty()) {
            instance.testParameter.setText(String.join(",", markedParameters));
        }
        instance.refreshConflicts();
        instance.refreshAdvancedTabs();

        JDialog dialog = new JDialog(parent, "Commix scan options", Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setContentPane(instance.buildContent(dialog));
        dialog.setMinimumSize(new Dimension(560, 580));
        dialog.setSize(640, 680);
        dialog.setLocationRelativeTo(parent);
        dialog.setVisible(true);

        if (!instance.started) {
            return Optional.empty();
        }
        instance.save();
        return Optional.of(instance.toOptionsMap());
    }

    private JPanel buildContent(JDialog dialog) {
        JPanel content = new JPanel(new BorderLayout());
        content.add(header(), BorderLayout.NORTH);

        tabs.addTab("Detection", page(detectionPanel()));
        content.add(tabs, BorderLayout.CENTER);

        content.add(buttons(dialog), BorderLayout.SOUTH);
        return content;
    }

    private JPanel header() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(CommixLogo.header(28, "Command injection exploitation, powered by commix - without leaving Burp."), BorderLayout.CENTER);

        JPanel toggleRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 12, 2));
        toggleRow.add(advancedToggle);
        panel.add(toggleRow, BorderLayout.SOUTH);
        return panel;
    }

    /**
     * Injection, Session & request and Post-exploitation only show up once "Show advanced options"
     * is checked - Detection and Tamper cover a first scan on their own, and the other three are
     * where the long tail of less-common flags lives.
     */
    private void refreshAdvancedTabs() {
        removeTabIfPresent("Injection");
        removeTabIfPresent("Session & request");
        removeTabIfPresent("Post-exploitation");
        if (advancedToggle.isSelected()) {
            tabs.addTab("Injection", page(injectionPanel()));
            tabs.addTab("Session & request", page(sessionPanel()));
            tabs.addTab("Post-exploitation", page(postExploitationPanel()));
        }
    }

    private void removeTabIfPresent(String title) {
        int index = tabs.indexOfTab(title);
        if (index >= 0) {
            tabs.removeTabAt(index);
        }
    }

    private JPanel buttons(JDialog dialog) {
        JButton startButton = new JButton("Start Scan");
        startButton.setFont(startButton.getFont().deriveFont(Font.BOLD));
        JButton cancelButton = new JButton("Cancel");
        startButton.addActionListener(e -> {
            started = true;
            dialog.dispose();
        });
        cancelButton.addActionListener(e -> dialog.dispose());
        dialog.getRootPane().setDefaultButton(startButton);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 10));
        buttons.setBorder(new MatteBorder(1, 0, 0, 0, new Color(0xDD, 0xDD, 0xDD)));
        buttons.add(cancelButton);
        buttons.add(startButton);
        return buttons;
    }

    /**
     * Disables whichever side of a conflicting pair the user didn't just pick - called once up
     * front and again on every relevant toggle, so the dialog can never submit a combination
     * commix itself would refuse.
     */
    private void refreshConflicts() {
        boolean oobSelected = oob.isSelected();
        techResults.setEnabled(!oobSelected);
        techBoolean.setEnabled(!oobSelected);
        techTime.setEnabled(!oobSelected);
        techFile.setEnabled(!oobSelected);

        boolean mobileSelected = mobile.isSelected();
        boolean randomSelected = randomAgent.isSelected();
        mobile.setEnabled(!randomSelected);
        randomAgent.setEnabled(!mobileSelected);
    }

    /** Wraps a section's fields so they sit at the top of the tab, with room to breathe. */
    private static JScrollPane page(JPanel inner) {
        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));
        wrapper.add(inner, BorderLayout.NORTH);
        JScrollPane scroll = new JScrollPane(wrapper);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        return scroll;
    }

    private JPanel detectionPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints c = baseConstraints();

        addRow(panel, c, new JLabel("Level"), level);
        addRow(panel, c, new JLabel("Verbosity (-v, 0-4)"), verbosity);
        JPanel techniques = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        techniques.add(techResults);
        techniques.add(techBoolean);
        techniques.add(techTime);
        techniques.add(techFile);
        addRow(panel, c, new JLabel("Technique"), techniques);
        addFullWidth(panel, c, oob);
        addFullWidth(panel, c, skipWaf);
        addFullWidth(panel, c, skipHeuristics);
        addFullWidth(panel, c, proof);
        addFullWidth(panel, c, textOnly);
        addFullWidth(panel, c, smart);
        addFullWidth(panel, c, skipStatic);
        addFullWidth(panel, c, skipEmpty);
        addRow(panel, c, new JLabel("Web root (--web-root)"), webRoot);
        addRow(panel, c, new JLabel("Temp path (--tmp-path)"), tmpPath);

        addFullWidth(panel, c, sectionLabel("Manual detection markers"));
        addRow(panel, c, new JLabel("True-condition string (--string)"), stringField);
        addRow(panel, c, new JLabel("False-condition string (--not-string)"), notStringField);
        addRow(panel, c, new JLabel("True-condition regex (--regexp)"), regexpField);
        addRow(panel, c, new JLabel("True-condition HTTP code (--code)"), codeField);

        addFullWidth(panel, c, sectionLabel("Tamper scripts"));
        addRow(panel, c, new JLabel("Scripts (--tamper)"), tamperField);
        addFullWidth(panel, c, tamperHint());
        return panel;
    }

    private static JTextArea tamperHint() {
        JTextArea hint = new JTextArea("Comma-separated script names, e.g. space2comment,charencode - same as "
                + "--tamper on the command line. See commix's src/tamper/ folder for the full list.");
        hint.setEditable(false);
        hint.setOpaque(false);
        hint.setLineWrap(true);
        hint.setWrapStyleWord(true);
        hint.setForeground(MUTED);
        hint.setFont(UIManager.getFont("Label.font").deriveFont(11f));
        return hint;
    }

    private JPanel injectionPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints c = baseConstraints();
        addRow(panel, c, new JLabel("Code injection language (--eval)"), evalLanguage);
        addRow(panel, c, new JLabel("Test parameter(s) (-p)"), testParameter);
        addRow(panel, c, new JLabel("Skip parameter(s) (--skip)"), skipParameter);
        addRow(panel, c, new JLabel("Prefix (--prefix)"), prefix);
        addRow(panel, c, new JLabel("Suffix (--suffix)"), suffix);
        addRow(panel, c, new JLabel("Force target OS (--os)"), forceOs);
        addRow(panel, c, new JLabel("Max extraction length (--maxlen)"), maxLen);
        return panel;
    }

    private JPanel sessionPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints c = baseConstraints();
        addFullWidth(panel, c, flushSession);
        JPanel agentRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        agentRow.add(randomAgent);
        agentRow.add(mobile);
        addFullWidth(panel, c, agentRow);
        addFullWidth(panel, c, tor);
        addFullWidth(panel, c, unstable);
        addFullWidth(panel, c, ignoreRedirects);
        addFullWidth(panel, c, ignoreTimeouts);
        addFullWidth(panel, c, dropSetCookie);
        addRow(panel, c, new JLabel("Proxy (host:port)"), proxy);
        addRow(panel, c, new JLabel("HTTP auth type"), authType);
        addRow(panel, c, new JLabel("HTTP auth credentials"), authCred);
        addRow(panel, c, new JLabel("Ignore HTTP code(s) (--ignore-code)"), ignoreCode);
        addRow(panel, c, new JLabel("Abort on HTTP code(s) (--abort-code)"), abortCode);
        addRow(panel, c, new JLabel("Delay (sec)"), delay);
        addRow(panel, c, new JLabel("Jitter (--jitter)"), jitter);
        addRow(panel, c, new JLabel("Timeout (sec)"), timeout);
        addRow(panel, c, new JLabel("Retries"), retries);
        addRow(panel, c, new JLabel("Time-sec (--time-sec)"), timeSec);
        addRow(panel, c, new JLabel("Time limit, sec (--time-limit)"), timeLimit);
        addRow(panel, c, new JLabel("Threads (--threads, max 10)"), threads);
        return panel;
    }

    private JPanel postExploitationPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints c = baseConstraints();

        addRow(panel, c, new JLabel("Run command (--os-cmd)"), osCmd);

        addFullWidth(panel, c, sectionLabel("File access"));
        addRow(panel, c, new JLabel("Read file from target (--file-read)"), fileRead);
        addRow(panel, c, new JLabel("Write local file to target (--file-write)"), fileWrite);
        addRow(panel, c, new JLabel("Destination path on target (--file-dest)"), fileDest);
        addFullWidth(panel, c, commonFiles);

        addFullWidth(panel, c, sectionLabel("Enumeration"));
        JPanel enumeration = new JPanel(new GridLayout(0, 2, 6, 4));
        enumeration.add(enumAll);
        enumeration.add(enumCurrentUser);
        enumeration.add(enumHostname);
        enumeration.add(enumIsRoot);
        enumeration.add(enumIsAdmin);
        enumeration.add(enumSysInfo);
        enumeration.add(enumPrivileges);
        enumeration.add(enumUsers);
        enumeration.add(enumPasswords);
        enumeration.add(enumPsVersion);
        addFullWidth(panel, c, enumeration);
        return panel;
    }

    private static JLabel sectionLabel(String text) {
        JLabel label = new JLabel(text);
        label.setFont(label.getFont().deriveFont(Font.BOLD));
        label.setBorder(BorderFactory.createEmptyBorder(6, 0, 2, 0));
        return label;
    }

    private static GridBagConstraints baseConstraints() {
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(5, 5, 5, 5);
        c.anchor = GridBagConstraints.WEST;
        c.gridx = 0;
        c.gridy = 0;
        return c;
    }

    private static void addRow(JPanel panel, GridBagConstraints c, JLabel label, JComponent field) {
        c.gridx = 0;
        c.fill = GridBagConstraints.NONE;
        c.weightx = 0;
        panel.add(label, c);
        c.gridx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;
        if (field instanceof JTextField) {
            ((JTextField) field).setColumns(16);
        }
        panel.add(field, c);
        c.gridy++;
    }

    private static void addFullWidth(JPanel panel, GridBagConstraints c, JComponent field) {
        c.gridx = 0;
        c.gridwidth = 2;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;
        panel.add(field, c);
        c.gridwidth = 1;
        c.weightx = 0;
        c.gridy++;
    }

    // --- persistence: the dialog remembers what was last chosen, across scans and restarts ---

    private void load() {
        advancedToggle.setSelected(boolOrDefault("scan.show_advanced", false));
        level.setSelectedItem(intOrDefault("scan.level", 1));
        techResults.setSelected(boolOrDefault("scan.tech.r", true));
        techBoolean.setSelected(boolOrDefault("scan.tech.b", true));
        techTime.setSelected(boolOrDefault("scan.tech.t", true));
        techFile.setSelected(boolOrDefault("scan.tech.f", true));
        oob.setSelected(boolOrDefault("scan.oob", false));
        skipWaf.setSelected(boolOrDefault("scan.skip_waf", false));
        skipHeuristics.setSelected(boolOrDefault("scan.skip_heuristics", false));
        proof.setSelected(boolOrDefault("scan.proof", false));
        textOnly.setSelected(boolOrDefault("scan.text_only", false));
        smart.setSelected(boolOrDefault("scan.smart", false));
        skipStatic.setSelected(boolOrDefault("scan.skip_static", false));
        skipEmpty.setSelected(boolOrDefault("scan.skip_empty", false));
        webRoot.setText(stringOrDefault("scan.web_root", ""));
        tmpPath.setText(stringOrDefault("scan.tmp_path", ""));
        stringField.setText(stringOrDefault("scan.string", ""));
        notStringField.setText(stringOrDefault("scan.not_string", ""));
        regexpField.setText(stringOrDefault("scan.regexp", ""));
        codeField.setText(stringOrDefault("scan.code", ""));

        tamperField.setText(stringOrDefault("scan.tamper", ""));

        String savedEval = store.getString("scan.eval");
        evalLanguage.setSelectedItem(savedEval == null || savedEval.isEmpty() ? "(none)" : savedEval);
        testParameter.setText(stringOrDefault("scan.test_parameter", ""));
        skipParameter.setText(stringOrDefault("scan.skip_parameter", ""));
        prefix.setText(stringOrDefault("scan.prefix", ""));
        suffix.setText(stringOrDefault("scan.suffix", ""));
        String savedOs = store.getString("scan.os");
        forceOs.setSelectedItem(savedOs == null || savedOs.isEmpty() ? "(auto-detect)" : savedOs);
        maxLen.setText(stringOrDefault("scan.maxlen", ""));

        flushSession.setSelected(boolOrDefault("scan.flush_session", true));
        randomAgent.setSelected(boolOrDefault("scan.random_agent", false));
        mobile.setSelected(boolOrDefault("scan.mobile", false));
        tor.setSelected(boolOrDefault("scan.tor", false));
        unstable.setSelected(boolOrDefault("scan.unstable", false));
        ignoreRedirects.setSelected(boolOrDefault("scan.ignore_redirects", false));
        ignoreTimeouts.setSelected(boolOrDefault("scan.ignore_timeouts", false));
        dropSetCookie.setSelected(boolOrDefault("scan.drop_set_cookie", false));
        proxy.setText(stringOrDefault("scan.proxy", ""));
        String savedAuthType = store.getString("scan.auth_type");
        authType.setSelectedItem(savedAuthType == null || savedAuthType.isEmpty() ? "(none)" : savedAuthType);
        authCred.setText(stringOrDefault("scan.auth_cred", ""));
        ignoreCode.setText(stringOrDefault("scan.ignore_code", ""));
        abortCode.setText(stringOrDefault("scan.abort_code", ""));
        delay.setText(stringOrDefault("scan.delay", ""));
        jitter.setText(stringOrDefault("scan.jitter", ""));
        timeout.setText(stringOrDefault("scan.timeout", ""));
        retries.setText(stringOrDefault("scan.retries", ""));
        timeSec.setText(stringOrDefault("scan.time_sec", ""));
        timeLimit.setText(stringOrDefault("scan.time_limit", ""));
        threads.setValue(intOrDefault("scan.threads", 1));
        verbosity.setSelectedItem(intOrDefault("scan.verbose", 0));

        osCmd.setText(stringOrDefault("scan.os_cmd", ""));

        fileRead.setText(stringOrDefault("scan.file_read", ""));
        fileWrite.setText(stringOrDefault("scan.file_write", ""));
        fileDest.setText(stringOrDefault("scan.file_dest", ""));
        commonFiles.setSelected(boolOrDefault("scan.common_files", false));

        enumAll.setSelected(boolOrDefault("scan.all", false));
        enumCurrentUser.setSelected(boolOrDefault("scan.current_user", false));
        enumHostname.setSelected(boolOrDefault("scan.hostname", false));
        enumIsRoot.setSelected(boolOrDefault("scan.is_root", false));
        enumIsAdmin.setSelected(boolOrDefault("scan.is_admin", false));
        enumSysInfo.setSelected(boolOrDefault("scan.sys_info", false));
        enumPrivileges.setSelected(boolOrDefault("scan.privileges", false));
        enumUsers.setSelected(boolOrDefault("scan.users", false));
        enumPasswords.setSelected(boolOrDefault("scan.passwords", false));
        enumPsVersion.setSelected(boolOrDefault("scan.ps_version", false));
    }

    private void save() {
        store.setBoolean("scan.show_advanced", advancedToggle.isSelected());
        store.setInteger("scan.level", (Integer) level.getSelectedItem());
        store.setBoolean("scan.tech.r", techResults.isSelected());
        store.setBoolean("scan.tech.b", techBoolean.isSelected());
        store.setBoolean("scan.tech.t", techTime.isSelected());
        store.setBoolean("scan.tech.f", techFile.isSelected());
        store.setBoolean("scan.oob", oob.isSelected());
        store.setBoolean("scan.skip_waf", skipWaf.isSelected());
        store.setBoolean("scan.skip_heuristics", skipHeuristics.isSelected());
        store.setBoolean("scan.proof", proof.isSelected());
        store.setBoolean("scan.text_only", textOnly.isSelected());
        store.setBoolean("scan.smart", smart.isSelected());
        store.setBoolean("scan.skip_static", skipStatic.isSelected());
        store.setBoolean("scan.skip_empty", skipEmpty.isSelected());
        store.setString("scan.web_root", webRoot.getText().trim());
        store.setString("scan.tmp_path", tmpPath.getText().trim());
        store.setString("scan.string", stringField.getText().trim());
        store.setString("scan.not_string", notStringField.getText().trim());
        store.setString("scan.regexp", regexpField.getText().trim());
        store.setString("scan.code", codeField.getText().trim());

        store.setString("scan.tamper", tamperField.getText().trim());

        String selectedEval = (String) evalLanguage.getSelectedItem();
        store.setString("scan.eval", "(none)".equals(selectedEval) ? "" : selectedEval);
        store.setString("scan.test_parameter", testParameter.getText().trim());
        store.setString("scan.skip_parameter", skipParameter.getText().trim());
        store.setString("scan.prefix", prefix.getText().trim());
        store.setString("scan.suffix", suffix.getText().trim());
        String selectedOs = (String) forceOs.getSelectedItem();
        store.setString("scan.os", "(auto-detect)".equals(selectedOs) ? "" : selectedOs);
        store.setString("scan.maxlen", maxLen.getText().trim());

        store.setBoolean("scan.flush_session", flushSession.isSelected());
        store.setBoolean("scan.random_agent", randomAgent.isSelected());
        store.setBoolean("scan.mobile", mobile.isSelected());
        store.setBoolean("scan.tor", tor.isSelected());
        store.setBoolean("scan.unstable", unstable.isSelected());
        store.setBoolean("scan.ignore_redirects", ignoreRedirects.isSelected());
        store.setBoolean("scan.ignore_timeouts", ignoreTimeouts.isSelected());
        store.setBoolean("scan.drop_set_cookie", dropSetCookie.isSelected());
        store.setString("scan.proxy", proxy.getText().trim());
        String selectedAuthType = (String) authType.getSelectedItem();
        store.setString("scan.auth_type", "(none)".equals(selectedAuthType) ? "" : selectedAuthType);
        store.setString("scan.auth_cred", authCred.getText().trim());
        store.setString("scan.ignore_code", ignoreCode.getText().trim());
        store.setString("scan.abort_code", abortCode.getText().trim());
        store.setString("scan.delay", delay.getText().trim());
        store.setString("scan.jitter", jitter.getText().trim());
        store.setString("scan.timeout", timeout.getText().trim());
        store.setString("scan.retries", retries.getText().trim());
        store.setString("scan.time_sec", timeSec.getText().trim());
        store.setString("scan.time_limit", timeLimit.getText().trim());
        store.setInteger("scan.threads", (Integer) threads.getValue());
        store.setInteger("scan.verbose", (Integer) verbosity.getSelectedItem());

        store.setString("scan.os_cmd", osCmd.getText().trim());

        store.setString("scan.file_read", fileRead.getText().trim());
        store.setString("scan.file_write", fileWrite.getText().trim());
        store.setString("scan.file_dest", fileDest.getText().trim());
        store.setBoolean("scan.common_files", commonFiles.isSelected());

        store.setBoolean("scan.all", enumAll.isSelected());
        store.setBoolean("scan.current_user", enumCurrentUser.isSelected());
        store.setBoolean("scan.hostname", enumHostname.isSelected());
        store.setBoolean("scan.is_root", enumIsRoot.isSelected());
        store.setBoolean("scan.is_admin", enumIsAdmin.isSelected());
        store.setBoolean("scan.sys_info", enumSysInfo.isSelected());
        store.setBoolean("scan.privileges", enumPrivileges.isSelected());
        store.setBoolean("scan.users", enumUsers.isSelected());
        store.setBoolean("scan.passwords", enumPasswords.isSelected());
        store.setBoolean("scan.ps_version", enumPsVersion.isSelected());
    }

    private boolean boolOrDefault(String key, boolean fallback) {
        Boolean value = store.getBoolean(key);
        return value == null ? fallback : value;
    }

    private int intOrDefault(String key, int fallback) {
        Integer value = store.getInteger(key);
        return value == null ? fallback : value;
    }

    private String stringOrDefault(String key, String fallback) {
        String value = store.getString(key);
        return value == null ? fallback : value;
    }

    // --- turning what was chosen into the options commix's API takes ---

    private Map<String, Object> toOptionsMap() {
        Map<String, Object> options = new LinkedHashMap<>();
        options.put("level", level.getSelectedItem());

        boolean oobSelected = oob.isSelected();
        if (oobSelected) {
            // commix's own validation refuses --oob together with --technique - never send both,
            // even though the technique checkboxes keep whatever they were checked to before oob
            // was picked (so unchecking oob again restores them).
            options.put("oob", true);
        } else {
            String technique = (techResults.isSelected() ? "r" : "")
                    + (techBoolean.isSelected() ? "b" : "")
                    + (techTime.isSelected() ? "t" : "")
                    + (techFile.isSelected() ? "f" : "");
            if (!technique.isEmpty()) {
                options.put("technique", technique);
            }
        }
        if (skipWaf.isSelected()) {
            options.put("skip_waf", true);
        }
        if (skipHeuristics.isSelected()) {
            options.put("skip_heuristics", true);
        }
        if (proof.isSelected()) {
            options.put("proof", true);
        }
        if (textOnly.isSelected()) {
            options.put("text_only", true);
        }
        if (smart.isSelected()) {
            options.put("smart", true);
        }
        if (skipStatic.isSelected()) {
            options.put("skip_static", true);
        }
        if (skipEmpty.isSelected()) {
            options.put("skip_empty", true);
        }
        putIfNonEmpty(options, "web_root", webRoot.getText());
        putIfNonEmpty(options, "tmp_path", tmpPath.getText());
        putIfNonEmpty(options, "string", stringField.getText());
        putIfNonEmpty(options, "not_string", notStringField.getText());
        putIfNonEmpty(options, "regexp", regexpField.getText());
        putIfNonEmpty(options, "code", codeField.getText());

        String tamper = tamperField.getText().trim();
        if (!tamper.isEmpty()) {
            options.put("tamper", tamper);
        }

        String selectedEval = (String) evalLanguage.getSelectedItem();
        if (selectedEval != null && !"(none)".equals(selectedEval)) {
            options.put("eval", selectedEval);
        }
        putIfNonEmpty(options, "test_parameter", testParameter.getText());
        putIfNonEmpty(options, "skip", skipParameter.getText());
        putIfNonEmpty(options, "prefix", prefix.getText());
        putIfNonEmpty(options, "suffix", suffix.getText());
        String selectedOs = (String) forceOs.getSelectedItem();
        if (selectedOs != null && !"(auto-detect)".equals(selectedOs)) {
            options.put("os", selectedOs);
        }
        putIfNonEmpty(options, "maxlen", maxLen.getText());

        if (flushSession.isSelected()) {
            options.put("flush_session", true);
        }
        // random_agent and mobile can't both be sent - the dialog itself never lets both end up
        // checked, so whichever is true here is the only one that could be.
        if (randomAgent.isSelected()) {
            options.put("random_agent", true);
        }
        if (mobile.isSelected()) {
            options.put("mobile", true);
        }
        if (tor.isSelected()) {
            options.put("tor", true);
        }
        if (unstable.isSelected()) {
            options.put("unstable", true);
        }
        if (ignoreRedirects.isSelected()) {
            options.put("ignore_redirects", true);
        }
        if (ignoreTimeouts.isSelected()) {
            options.put("ignore_timeouts", true);
        }
        if (dropSetCookie.isSelected()) {
            options.put("drop_set_cookie", true);
        }
        putIfNonEmpty(options, "proxy", proxy.getText());
        String selectedAuthType = (String) authType.getSelectedItem();
        if (selectedAuthType != null && !"(none)".equals(selectedAuthType)) {
            options.put("auth_type", selectedAuthType);
            putIfNonEmpty(options, "auth_cred", authCred.getText());
        }
        putIfNonEmpty(options, "ignore_code", ignoreCode.getText());
        putIfNonEmpty(options, "abort_code", abortCode.getText());
        putIfNonEmpty(options, "delay", delay.getText());
        putIfNonEmpty(options, "jitter", jitter.getText());
        putIfNonEmpty(options, "timeout", timeout.getText());
        putIfNonEmpty(options, "retries", retries.getText());
        putIfNonEmpty(options, "time_sec", timeSec.getText());
        putIfNonEmpty(options, "time_limit", timeLimit.getText());
        int threadsValue = (Integer) threads.getValue();
        if (threadsValue > 1) {
            options.put("threads", threadsValue);
        }
        int verbosityValue = (Integer) verbosity.getSelectedItem();
        if (verbosityValue > 0) {
            options.put("verbose", verbosityValue);
        }

        putIfNonEmpty(options, "os_cmd", osCmd.getText());

        putIfNonEmpty(options, "file_read", fileRead.getText());
        putIfNonEmpty(options, "file_write", fileWrite.getText());
        putIfNonEmpty(options, "file_dest", fileDest.getText());
        if (commonFiles.isSelected()) {
            options.put("common_files", true);
        }

        if (enumAll.isSelected()) {
            options.put("all", true);
        }
        if (enumCurrentUser.isSelected()) {
            options.put("current_user", true);
        }
        if (enumHostname.isSelected()) {
            options.put("hostname", true);
        }
        if (enumIsRoot.isSelected()) {
            options.put("is_root", true);
        }
        if (enumIsAdmin.isSelected()) {
            options.put("is_admin", true);
        }
        if (enumSysInfo.isSelected()) {
            options.put("sys_info", true);
        }
        if (enumPrivileges.isSelected()) {
            options.put("privileges", true);
        }
        if (enumUsers.isSelected()) {
            options.put("users", true);
        }
        if (enumPasswords.isSelected()) {
            options.put("passwords", true);
        }
        if (enumPsVersion.isSelected()) {
            options.put("ps_version", true);
        }

        return options;
    }

    private static void putIfNonEmpty(Map<String, Object> options, String key, String text) {
        String trimmed = text == null ? "" : text.trim();
        if (!trimmed.isEmpty()) {
            options.put(key, trimmed);
        }
    }
}
