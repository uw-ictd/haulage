# How can I report a problem?
If you've encountered a problem with haulage that warrants developer attention, the best way to track it is to report
the issue in the [public haulage issue tracker](https://github.com/uw-ictd/haulage/issues). Before you open a new issue,
check that your issue has not been already reported! It's much better to add more information to an existing ticket than
create a new ticket that will have to be de-duplicated later :smile:. A good issue report will include not only the
observed problem, but context like which version of haulage you were using, your system specifications, and what steps
can be taken to reproduce the problem!

# What do I need to know to help?
If you are looking to help to with a code contribution, our project uses Golang, MariaDB, systemd, and markdown. If you
don't feel ready to make a code contribution yet, no problem! You can also check out the [documentation
issues](https://github.com/uw-ictd/haulage/labels/docs).

If you are interested in making a code contribution and would like to learn more about the technologies that we use,
check out the list below.

 * Golang: [A Tour of Go](https://tour.golang.org/welcome/1)
 * MariaDB: [Get Started with MariaDB](https://mariadb.com/products/get-started)
 * systemd: [Digital Ocean's systemd Essentials](https://www.digitalocean.com/community/tutorials/systemd-essentials-working-with-services-units-and-the-journal)
 * markdown: [GitHub Guides: Mastering Markdown](https://guides.github.com/features/mastering-markdown/)

# How do I make a contribution?
Never made an open source contribution before? Wondering how contributions work in the in our project? Here's a quick
rundown!

1. Find an issue that you are interested in addressing or a feature that you would like to add.
2. Fork the repository associated with the issue to your local GitHub organization. This means that you will have a copy of the repository under your-GitHub-username/repository-name.
3. Clone the repository to your local machine using git clone https://github.com/github-username/repository-name.git.
4. Create a new branch for your fix using git checkout -b branch-name-here.
5. Make the appropriate changes for the issue you are trying to address or the feature that you want to add.
6. Use git add insert-paths-of-changed-files-here to add the file contents of the changed files to the "snapshot" git uses to manage the state of the project, also known as the index.
7. Use git commit -m "Insert a short message of the changes made here" to store the contents of the index with a descriptive message.
8. Push the changes to the remote repository using git push origin branch-name-here.
9. Submit a pull request to the upstream repository.
10. Title the pull request with a short description of the changes made and the issue or bug number associated with your change. For example, you can title an issue like so "Added more log outputting to resolve #4352".
11. In the description of the pull request, explain the changes that you made, any issues you think exist with the pull request you made, and any questions you have for the maintainer. It's OK if your pull request is not perfect (no pull request is), the reviewer will be able to help you fix any problems and improve it!
12. Wait for the pull request to be reviewed by a maintainer.
13. Make changes to the pull request if the reviewing maintainer recommends them.
14. Celebrate your success after your pull request is merged!

## Code Style
As a golang project, all contributions must adhere to the [go fmt](https://blog.golang.org/go-fmt-your-code) standard
and pass [golint](https://github.com/golang/lint). Naming and comment styles should follow the golang best practices in
[Effective Go](https://golang.org/doc/effective_go.html). To help keep issues in the open, todos in code merged to
master must be of the format `// TODO(####) Comment text here` where `####` is an open github issue number.

# Where can I go for help?
If you need help, please check the mailing list archive or ask a new question on the list
[https://groups.google.com/forum/#!forum/haulage](https://groups.google.com/forum/#!forum/haulage).

# Love
Thank you for your interest in the haulage project! Open source only lives via your help and support!

---
This contibution guide is modified from the [template at
opensource.com](https://opensource.com/life/16/3/contributor-guidelines-template-and-tips) written by Safia Abdalla, and
is made available under the [CC BY-SA 4.0 license](https://creativecommons.org/licenses/by-sa/4.0/)
