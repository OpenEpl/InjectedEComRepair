﻿using System;
using System.Collections.Generic;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace InjectedEComRepair
{
    public partial class InputPasswordDialog : Window
    {
        public string Password;
        public InputPasswordDialog(string tips = null)
        {
            InitializeComponent();
            this.TipsTextBox.Text = string.IsNullOrWhiteSpace(tips) ? "[无]" : tips;
        }

        private void OKButton_Click(object sender, RoutedEventArgs e)
        {
            this.DialogResult = true;
            this.Password = PasswordTextBox.Password;
            this.Close();
        }
    }
}
